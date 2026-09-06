# Copyright 2018-2021 Akretion France (https://www.akretion.com/)
# @author: Alexis de Lattre <alexis.delattre@akretion.com>

from odoo import api, fields, models, _
from odoo.tools import file_open, file_path
from odoo.exceptions import UserError
import lxml.etree as ET
import requests
import subprocess
from tempfile import NamedTemporaryFile
import re
import os
import base64
import hashlib
import mimetypes
from lxml import etree
from lxml.isoschematron import Schematron
import saxonche
from collections import defaultdict
from pypdf import PdfReader
from pypdf.generic import IndirectObject
from facturx import xml_check_xsd, get_flavor as _get_flavor_orig, get_orderx_type
import logging
logger = logging.getLogger(__name__)

FACTURX_FILENAME = 'factur-x.xml'
ORDERX_FILENAME = 'order-x.xml'
UBL_FILENAME = 'ubl.xml'
CII_FILENAME = 'cii.xml'
CDAR_FILENAME = 'cdar.xml'
EREPORTING_FILENAME = 'ereporting.xml'
ALL_FILENAMES = [FACTURX_FILENAME, ORDERX_FILENAME,UBL_FILENAME,CII_FILENAME,CDAR_FILENAME,EREPORTING_FILENAME]

FACTURX_XML_FX_NAMESPACES = {
    'qdt': 'urn:un:unece:uncefact:data:standard:QualifiedDataType:100',
    'ram': 'urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100',
    'rsm': 'urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100',
    'udt': 'urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
}

ORDERX_XML_NAMESPACES = {
    'qdt': 'urn:un:unece:uncefact:data:standard:QualifiedDataType:128',
    'ram': 'urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:128',
    'rsm': 'urn:un:unece:uncefact:data:SCRDMCCBDACIOMessageStructure:100',
    'udt': 'urn:un:unece:uncefact:data:standard:UnqualifiedDataType:128',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

#---------------ADDED by SMV 02/06/2026----------------

# UBL root tag namespaces (Invoice and CreditNote)
UBL_ROOT_NAMESPACES = (
    'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
    'urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2',
    )

CDAR_XML_NAMESPACES = {
    'qdt': 'urn:un:unece:uncefact:data:standard:QualifiedDataType:100',
    'udt': 'urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100',
    'ram': 'urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100',
    'rsm': 'urn:un:unece:uncefact:data:standard:CrossDomainAcknowledgementAndResponse:100',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
}

#e-Reporting_XML_NAMESPACES = { will be added later}

#------------------END NAMESPACES MODIFICTION-------------------

# 3rd element = the context URN that identifies this profile:
#  - Factur-X / CII rows: the GuidelineSpecifiedDocumentContextParameter/ram:ID.
#    Only listed where it is UNAMBIGUOUS between Factur-X and native CII (i.e.
#    it carries an explicit "factur-x.eu" or "cpro.gouv.fr" marker). The bare
#    'urn:cen.eu:en16931:2017' is shared by facturx_en16931 AND cii_en16931,
#    so it is deliberately NOT listed -- those stay disambiguated by file_type
#    (pdf -> Factur-X, standalone xml -> CII). Values verified against
#    France_RFE/FNFE_RFE_INVOICE/Z.example/TEST; minimum/basic are the
#    canonical Factur-X 1.0 URNs (no example ships for them).
#  - UBL rows: the cbc:CustomizationID.
_PROFILES_DEF = [
    ('facturx_minimum',         'Minimum',                'urn:factur-x.eu:1p0:minimum'),
    ('facturx_basicwl',         'Basic WL',               'urn:factur-x.eu:1p0:basicwl'),
    ('facturx_basic',           'Basic',                  'urn:cen.eu:en16931:2017#compliant#urn:factur-x.eu:1p0:basic'),
    ('facturx_en16931',         'EN 16931 (Comfort)'),
    ('facturx_extended',        'Extended',               'urn:cen.eu:en16931:2017#conformant#urn:factur-x.eu:1p0:extended'),
    ('facturx_extended_ctc_fr', 'Extended-CTC-FR'),
    ('orderx_basic',            'Basic (Order-X)'),
    ('orderx_comfort',          'Comfort (Order-X)'),
    ('orderx_extended',         'Extended (Order-X)'),
    ('cii_en16931',             'EN 16931 (CII)'),
    ('cii_extended',            'Extended (CII)'),
    ('cii_extended_ctc_fr',     'Extended-CTC-FR (CII)',  'urn:cen.eu:en16931:2017#conformant#urn.cpro.gouv.fr:1p0:extended-ctc-fr'),
    ('ubl_en16931',             'EN 16931 (UBL)',         'urn:cen.eu:en16931:2017'),
    ('ubl_extended_ctc_fr',     'Extended-CTC-FR (UBL)', 'urn:cen.eu:en16931:2017#conformant#urn.cpro.gouv.fr:1p0:extended-ctc-fr'),
    ('ubl_extended',            'Extended (UBL)'),
    ('cdar_ctc_fr',             'CDAR CTC-FR'),
    ('ereporting',              'e-Reporting'),
    ]

PROFILES = [(p[0], p[1]) for p in _PROFILES_DEF]
# CustomizationID -> profile, UBL only (the CII CTC-FR URN is the same string,
# hence the ubl_ guard so the two maps never cross).
UBL_PROFILE_MAP = [(p[2], p[0]) for p in _PROFILES_DEF
                   if len(p) == 3 and p[0].startswith('ubl_')]
# Guideline context URN -> profile, for the CII-syntax formats (Factur-X, CII).
GUIDELINE_PROFILE_MAP = {p[2]: p[0] for p in _PROFILES_DEF
                         if len(p) == 3 and not p[0].startswith('ubl_')}


# --- one place per business profile for every ruleset the analysis loads ---
# Replaces the old SCH_PATHS / XSL_PATHS / ad-hoc XSD strings.
#   schematron           .sch source (human ref; run directly only for Order-X
#                         via lxml isoschematron)
#   schematron_xslt      compiled .xslt actually executed by Saxon
#   br_fr_schematron[_xslt]  the systematic BR-FR pass, now shipped per profile
#                         by the FNFE (github.com/fnfempe/France_RFE). Absent
#                         for the legacy Factur-X profiles and Order-X.
#   xsd                   entry-point XSD in the FNFE tree; sibling xs:import
#                         files sit next to it. Absent -> fall back to the
#                         `facturx` PyPI package's bundled schema.
# All paths are Odoo file_path()-relative (addon-rooted). _FR = the FNFE
# France_RFE tree, _SD = the in-repo SCRDM-Doc-X tree (legacy + Order-X).
_FR = 'facturx_validator/France_RFE/FNFE_RFE_INVOICE'
_SD = 'facturx_validator/SCRDM-Doc-X'

PROFILE_RULES = {
    # -- legacy Factur-X: SCRDM-Doc-X, no BR-FR pass, no repo XSD --
    'facturx_minimum': {
        'schematron':      _SD + '/Factur-X/LEGACY/MINIMUM/schematron/FACTUR-X_MINIMUM.sch',
        'schematron_xslt': _SD + '/Factur-X/LEGACY/MINIMUM/2xslt/FACTUR-X_MINIMUM.xslt',
    },
    'facturx_basic': {
        'schematron':      _SD + '/Factur-X/LEGACY/BASIC/schematron/FACTUR-X_BASIC.sch',
        'schematron_xslt': _SD + '/Factur-X/LEGACY/BASIC/2xslt/FACTUR-X_BASIC.xslt',
    },
    # -- Factur-X / CII / UBL / CDAR: FNFE France_RFE, per-profile BR-FR --
    'facturx_basicwl': {
        'schematron':            _FR + '/Factur-X/BASICWL/schematron/FACTUR-X_BASIC-WL.sch',
        'schematron_xslt':       _FR + '/Factur-X/BASICWL/2xslt/FACTUR-X_BASIC-WL.xslt',
        'br_fr_schematron':      _FR + '/Factur-X/BASICWL/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/Factur-X/BASICWL/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/Factur-X/BASICWL/1xsd/Factur-X_BASICWL.xsd',
    },
    'facturx_en16931': {
        'schematron':            _FR + '/Factur-X/EN16931/schematron/FACTUR-X_EN16931.sch',
        'schematron_xslt':       _FR + '/Factur-X/EN16931/2xslt/FACTUR-X_EN16931.xslt',
        'br_fr_schematron':      _FR + '/Factur-X/EN16931/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/Factur-X/EN16931/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/Factur-X/EN16931/1xsd/Factur-X_EN16931.xsd',
    },
    'facturx_extended': {
        'schematron':            _FR + '/Factur-X/EXTENDED/schematron/FACTUR-X_EXTENDED.sch',
        'schematron_xslt':       _FR + '/Factur-X/EXTENDED/2xslt/FACTUR-X_EXTENDED.xslt',
        'br_fr_schematron':      _FR + '/Factur-X/EXTENDED/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/Factur-X/EXTENDED/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/Factur-X/EXTENDED/1xsd/Factur-X_EXTENDED.xsd',
    },
    # no dedicated Factur-X EXTENDED-CTC-FR ruleset in the FNFE tree: reuse
    # plain EXTENDED (unchanged from before).
    'facturx_extended_ctc_fr': {
        'schematron':            _FR + '/Factur-X/EXTENDED/schematron/FACTUR-X_EXTENDED.sch',
        'schematron_xslt':       _FR + '/Factur-X/EXTENDED/2xslt/FACTUR-X_EXTENDED.xslt',
        'br_fr_schematron':      _FR + '/Factur-X/EXTENDED/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/Factur-X/EXTENDED/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/Factur-X/EXTENDED/1xsd/Factur-X_EXTENDED.xsd',
    },
    'cii_en16931': {
        'schematron':            _FR + '/CII/EN16931/schematron/EN16931-CII-validation-preprocessed.sch',
        'schematron_xslt':       _FR + '/CII/EN16931/2xslt/EN16931-CII-validation.xslt',
        'br_fr_schematron':      _FR + '/CII/EN16931/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/CII/EN16931/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        # standalone CII: full unrestricted D22B schema (not a profile subset)
        'xsd':                   _FR + '/CII/1xsd-CII_D22B_uncoupled/CrossIndustryInvoice_100pD22B.xsd',
    },
    # no dedicated CII EXTENDED (non-CTC) profile schematron: reuse Factur-X
    # EXTENDED for the profile pass, CII EXTENDED-CTC-FR for the BR-FR pass.
    'cii_extended': {
        'schematron':            _FR + '/Factur-X/EXTENDED/schematron/FACTUR-X_EXTENDED.sch',
        'schematron_xslt':       _FR + '/Factur-X/EXTENDED/2xslt/FACTUR-X_EXTENDED.xslt',
        'br_fr_schematron':      _FR + '/CII/EXTENDED-CTC-FR/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/CII/EXTENDED-CTC-FR/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/CII/1xsd-CII_D22B_uncoupled/CrossIndustryInvoice_100pD22B.xsd',
    },
    'cii_extended_ctc_fr': {
        'schematron':            _FR + '/CII/EXTENDED-CTC-FR/schematron/EXTENDED-CTC-FR-CII.sch',
        'schematron_xslt':       _FR + '/CII/EXTENDED-CTC-FR/2xslt/EXTENDED-CTC-FR-CII.xslt',
        'br_fr_schematron':      _FR + '/CII/EXTENDED-CTC-FR/schematron/BR-FR-Flux2-Schematron-CII.sch',
        'br_fr_schematron_xslt': _FR + '/CII/EXTENDED-CTC-FR/2xslt/BR-FR-Flux2-Schematron-CII.xslt',
        'xsd':                   _FR + '/CII/1xsd-CII_D22B_uncoupled/CrossIndustryInvoice_100pD22B.xsd',
    },
    'ubl_en16931': {
        'schematron':            _FR + '/UBL/EN16931/schematron/EN16931-UBL-validation-preprocessed.sch',
        'schematron_xslt':       _FR + '/UBL/EN16931/2xslt/EN16931-UBL-validation.xslt',
        'br_fr_schematron':      _FR + '/UBL/EN16931/schematron/BR-FR-Flux2-Schematron-UBL.sch',
        'br_fr_schematron_xslt': _FR + '/UBL/EN16931/2xslt/BR-FR-Flux2-Schematron-UBL.xslt',
        # UBL XSD (UBL-Invoice-2.1 vs UBL-CreditNote-2.1) is picked at runtime
        # in analyse_xml_xsd; the folder is fixed here for the report.
        'xsd_dir':               _FR + '/UBL/1xsd_UBL2.1/maindoc',
    },
    'ubl_extended_ctc_fr': {
        'schematron':            _FR + '/UBL/EXTENDED-CTC-FR/schematron/EXTENDED-CTC-FR-UBL.sch',
        'schematron_xslt':       _FR + '/UBL/EXTENDED-CTC-FR/2xslt/EXTENDED-CTC-FR-UBL.xslt',
        'br_fr_schematron':      _FR + '/UBL/EXTENDED-CTC-FR/schematron/BR-FR-Flux2-Schematron-UBL.sch',
        'br_fr_schematron_xslt': _FR + '/UBL/EXTENDED-CTC-FR/2xslt/BR-FR-Flux2-Schematron-UBL.xslt',
        'xsd_dir':               _FR + '/UBL/1xsd_UBL2.1/maindoc',
    },
    # no dedicated plain-EXTENDED UBL ruleset: reuse EXTENDED-CTC-FR.
    'ubl_extended': {
        'schematron':            _FR + '/UBL/EXTENDED-CTC-FR/schematron/EXTENDED-CTC-FR-UBL.sch',
        'schematron_xslt':       _FR + '/UBL/EXTENDED-CTC-FR/2xslt/EXTENDED-CTC-FR-UBL.xslt',
        'br_fr_schematron':      _FR + '/UBL/EXTENDED-CTC-FR/schematron/BR-FR-Flux2-Schematron-UBL.sch',
        'br_fr_schematron_xslt': _FR + '/UBL/EXTENDED-CTC-FR/2xslt/BR-FR-Flux2-Schematron-UBL.xslt',
        'xsd_dir':               _FR + '/UBL/1xsd_UBL2.1/maindoc',
    },
    # CDAR: the FNFE ships a single BR-FR-CDV ruleset that IS the whole
    # schematron -- profile pass and BR-FR pass are the same file, run once.
    'cdar_ctc_fr': {
        'schematron':      _FR + '/CDAR/schematron/BR-FR-CDV-Schematron-CDAR.sch',
        'schematron_xslt': _FR + '/CDAR/2xslt/BR-FR-CDV-Schematron-CDAR.xslt',
        'xsd':             _FR + '/CDAR/1xsd-CDAR_D22B_uncoupled/CrossDomainAcknowledgementAndResponse_100pD22B.xsd',
    },
    # Order-X: SCRDM-Doc-X, lxml isoschematron path reads 'schematron'.
    'orderx_basic': {
        'schematron':      _SD + '/Order-X/BASIC/schematron/SCRDMCCBDACIOMessageStructure_100pD20B_BASIC.sch',
        'schematron_xslt': _SD + '/Order-X/BASIC/2xslt/SCRDMCCBDACIOMessageStructure_100pD20B_BASIC-compiled.xslt',
    },
    'orderx_comfort': {
        'schematron':      _SD + '/Order-X/COMFORT/schematron/SCRDMCCBDACIOMessageStructure_100pD20B_COMFORT.sch',
        'schematron_xslt': _SD + '/Order-X/COMFORT/2xslt/SCRDMCCBDACIOMessageStructure_100pD20B_COMFORT-compiled.xslt',
    },
    'orderx_extended': {
        'schematron':      _SD + '/Order-X/EXTENDED/schematron/SCRDMCCBDACIOMessageStructure_100pD20B_EXTENDED.sch',
        'schematron_xslt': _SD + '/Order-X/EXTENDED/2xslt/SCRDMCCBDACIOMessageStructure_100pD20B_EXTENDED-compiled.xslt',
    },
}

ORDERX_TYPES = [
    ('order', 'Order'),
    ('order_response', 'Order Response'),
    ('order_change', 'Order Change'),
    ]

FACTURX_xmp2level = {
    'MINIMUM': 'facturx_minimum',
    'BASIC WL': 'facturx_basicwl',
    'BASIC': 'facturx_basic',
    'EN 16931': 'facturx_en16931',
    'EXTENDED': 'facturx_extended',
    'EXTENDED CTC FR': 'facturx_extended_ctc_fr',
    }

ORDERX_xmp2level = {
    'BASIC': 'orderx_basic',
    'COMFORT': 'orderx_comfort',
    'EXTENDED': 'orderx_extended',
    }

SCHEMATRON_GROUPS = ('4_xml_schematron_profile', '5_xml_schematron_br_fr')


def get_flavor(xml_etree):
    """Extension locale de get_flavor() (upstream: akretion/factur-x).
    Ajoute la détection des formats non couverts par la lib pip."""
    logger.debug('get_flavor: tag=%s', xml_etree.tag)
    tag = xml_etree.tag
    if '{' in tag:
        ns = tag[1:tag.index('}')]
        if ns in UBL_ROOT_NAMESPACES:
            logger.debug('get_flavor: result=ubl')
            return 'ubl'
        if ns == CDAR_XML_NAMESPACES['rsm']:
            logger.debug('get_flavor: result=cdar')
            return 'cdar'
        # TODO e-Reporting: ajouter ici le root namespace quand le cahier des charges sera disponible
        # if ns == 'urn:...:e-Reporting:...':
        #     return 'ereporting'
    flavor = _get_flavor_orig(xml_etree)
    logger.debug('get_flavor: result=%s', flavor)
    return flavor


class FacturxAnalysis(models.Model):
    _name = 'facturx.analysis'
    _description = 'Factur-X Analysis and Validation'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'id desc'

    name = fields.Char(string='Number', readonly=True, copy=False)  # sequence
    partner_id = fields.Many2one(
        'res.partner', string='Partner', ondelete='restrict', tracking=True)
    title = fields.Char(string='Title', tracking=True)
    br_fr_check = fields.Boolean(
        string='France', default=True, tracking=True,
        help="Enabled (default): the systematic French CTC rules (BR-FR "
             "schematron, pass 2) run and are blocking -- a violation fails "
             "the analysis. Disabled: the BR-FR schematron is not run at all, "
             "it produces no findings and does not enter the schematron "
             "verdict (only the Profile schematron is then considered).")
    date = fields.Datetime(string='Analysis Date', readonly=True, copy=False)
    facturx_file = fields.Binary(
        string='File', copy=False)
    facturx_filename = fields.Char(
        string='Filename', copy=False, tracking=True)
    facturx_file_sha1 = fields.Char(
        string='SHA1 Sum', readonly=True, copy=False, tracking=True)
    facturx_file_size = fields.Integer(
        string='File Size', readonly=True, copy=False,
        tracking=True)
    file_type = fields.Selection([
        ('pdf', 'PDF'),
        ('xml', 'XML'),
        ], string='File Type', readonly=True, copy=False)
    state = fields.Selection(
        [('draft', 'Draft'), ('done', 'Done')],
        string='State', readonly=True, default='draft', copy=False,
        tracking=True)
    pdfa3_valid = fields.Boolean(string='Valid PDF/A-3', readonly=True, copy=False)
    xmp_valid = fields.Boolean('Valid XMP', readonly=True, copy=False)
    xml_valid = fields.Boolean(
        'XML valid against XSD', readonly=True, copy=False)
    xml_schematron_valid = fields.Boolean(
        'XML valid against Schematron', readonly=True, copy=False)
    # Per-pass schematron result: pass 1 is the Profile schematron
    # (4_xml_schematron_profile), pass 2 is the systematic BR-FR schematron
    # (5_xml_schematron_br_fr). They must stay separate even when a pass
    # finds no error, so each conformance result can be reported on its own.
    xml_schematron_profile_valid = fields.Boolean(
        'XML valid against Profile Schematron', readonly=True, copy=False)
    xml_schematron_br_fr_valid = fields.Boolean(
        'XML valid against BR-FR Schematron', readonly=True, copy=False)
    valid = fields.Boolean('Fully Valid', readonly=True, copy=False)
    xmp_profile = fields.Selection(
        PROFILES, string='XMP Profile', readonly=True, copy=False)
    xml_profile = fields.Selection(
        PROFILES, string='XML Profile', readonly=True, copy=False)
    error_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id', string='Errors',
        readonly=True)
    # Split of error_ids per error_group: the embedded list widget of a
    # one2many field cannot group its rows in the form view (no native
    # group_by support for x2many list views), so we expose one filtered
    # sub-list per group and let the view show each one under its own
    # header, matching the split already done for the printed report
    # in report_get_errors().
    error_pdfa3_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id', string='PDF/A-3 Errors',
        compute='_compute_error_ids_by_group')
    error_xmp_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id', string='XMP Errors',
        compute='_compute_error_ids_by_group')
    error_xml_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id', string='XML XSD Errors',
        compute='_compute_error_ids_by_group')
    error_schematron_profile_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id',
        string='XML Schematron Profile Errors',
        compute='_compute_error_ids_by_group')
    error_schematron_br_fr_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id',
        string='XML Schematron BR-FR Errors',
        compute='_compute_error_ids_by_group')
    xmp_file = fields.Binary(string='XMP File', readonly=True, copy=False)
    xmp_filename = fields.Char(readonly=True, copy=False)
    xml_file = fields.Binary(string='XML File', readonly=True, copy=False)
    xml_filename = fields.Char(readonly=True, copy=False)
    doc_type = fields.Selection([
        ('facturx', 'Factur-X'),
        ('orderx', 'Order-X'),
        ('ubl', 'UBL'),
        ('cii', 'CII'),
        ('cdar', 'CDAR'),
        ('ereporting', 'E-Reporting')
        ], readonly=True, tracking=True)
    xml_orderx_type = fields.Selection(
        ORDERX_TYPES, string='XML Order-X Type', readonly=True, copy=False)
    xmp_orderx_type = fields.Selection(
        ORDERX_TYPES, string='XMP Order-X Type', readonly=True, copy=False)
    afrelationship = fields.Char(string='AFRelationship', readonly=True, copy=False)
    # Per-verdict "which artefact judged it", filled during analyse() and shown
    # next to each verdict so a non-developer running a pre-release check can
    # see exactly what pronounced pass/fail.
    pdfa3_engine = fields.Char(
        string='PDF/A-3 Engine', readonly=True, copy=False,
        help="Which veraPDF path ran the PDF/A-3 check.")
    xsd_ruleset = fields.Char(
        string='XSD', readonly=True, copy=False,
        help="Schema the XML was validated against (entry-point file; its "
             "xs:import siblings sit in the same folder).")
    schematron_profile_ruleset = fields.Char(
        string='Profile Schematron', readonly=True, copy=False)
    schematron_br_fr_ruleset = fields.Char(
        string='BR-FR Schematron', readonly=True, copy=False)
    # Count of non-blocking schematron messages (severity 'warning' or 'info').
    # A document can be Fully Valid and still carry a non-zero count.
    # Stored so it can be used in search filters / list columns.
    nonblocking_count = fields.Integer(
        string='Warnings', compute='_compute_nonblocking_count',
        store=True)

    @api.model
    def create(self, vals):
        if vals.get('name', '/') == '/':
            vals['name'] = self.env['ir.sequence'].next_by_code(
                'facturx.analysis')
        return super(FacturxAnalysis, self).create(vals)

    @api.depends('error_ids.error_group')
    def _compute_error_ids_by_group(self):
        for rec in self:
            rec.error_pdfa3_ids = rec.error_ids.filtered(
                lambda e: e.error_group == '1_pdfa3')
            rec.error_xmp_ids = rec.error_ids.filtered(
                lambda e: e.error_group == '2_xmp')
            rec.error_xml_ids = rec.error_ids.filtered(
                lambda e: e.error_group == '3_xml')
            rec.error_schematron_profile_ids = rec.error_ids.filtered(
                lambda e: e.error_group == '4_xml_schematron_profile')
            rec.error_schematron_br_fr_ids = rec.error_ids.filtered(
                lambda e: e.error_group == '5_xml_schematron_br_fr')

    @api.depends('error_ids.severity')
    def _compute_nonblocking_count(self):
        for rec in self:
            rec.nonblocking_count = len(rec.error_ids.filtered(
                lambda e: e.severity != 'fatal'))

    def back_to_draft(self):
        self.ensure_one()
        self.write({
            'state': 'draft',
            'pdfa3_valid': False,
            'xmp_valid': False,
            'xml_valid': False,
            'xml_schematron_valid': False,
            'xml_schematron_profile_valid': False,
            'xml_schematron_br_fr_valid': False,
            'valid': False,
            'xmp_profile': False,
            'xml_profile': False,
            'date': False,
            'error_ids': [(6, 0, [])],
            'facturx_file_size': False,
            'facturx_file_sha1': False,
            'xml_file': False,
            'xml_filename': False,
            'xmp_file': False,
            'xmp_filename': False,
            'file_type': False,
            'doc_type': False,
            'xml_orderx_type': False,
            'xmp_orderx_type': False,
            'afrelationship': False,
            'pdfa3_engine': False,
            'xsd_ruleset': False,
            'schematron_profile_ruleset': False,
            'schematron_br_fr_ruleset': False,
        })

    @api.model
    def errors2errors_write(self, errors):
        errors_write = []
        for error_group, err_list in errors.items():
            for err in err_list:
                assert isinstance(err, dict)
                errors_write.append((0, 0, dict(err, error_group=error_group)))
        return errors_write

    def analyse(self):
        self.ensure_one()
        logger.info('Start analysis of %s', self.name)
        if not self.facturx_file:
            raise UserError(_("Missing Factur-X File"))
        filetype = mimetypes.guess_type(self.facturx_filename)
        logger.debug('Factur-X file mimetype: %s', filetype)
        vals = {'file_type': 'pdf'}
        errors = {
            '1_pdfa3': [],
            '2_xmp': [],
            '3_xml': [],
            '4_xml_schematron_profile': [],
            '5_xml_schematron_br_fr': [],
            #'6_xml_schematron_cpro': [],
        }
        if filetype:
            if filetype[0] == 'application/xml':
                vals['file_type'] = 'xml'
            elif filetype[0] != 'application/pdf':
                raise UserError(_(
                    "The Factur-X file has not been recognised as a PDF file "
                    "(MIME Type: %s). Please check the filename extension.")
                    % filetype[0])
        prefix = self.facturx_filename and self.facturx_filename[:4] + '-'\
            or 'facturx-'
        suffix = '.%s' % vals['file_type']
        f = NamedTemporaryFile('wb+', prefix=prefix, suffix=suffix)
        f.write(base64.decodebytes(self.facturx_file))
        f.seek(0)
        if vals['file_type'] == 'pdf':
            try:
                pdf = PdfReader(f)
                pdf_root = pdf.trailer['/Root']
            except Exception:
                raise UserError(_("This is not a PDF file"))
            rest = False
            try:
                logger.info('Connecting to veraPDF via Rest')
                vera_xml_root = self.run_verapdf_rest(vals, f)
                rest = True
            except Exception as e:
                logger.warning(
                    'Failed to connect to veraPDF via Rest. Error: %s'
                    'Fallback to subprocess method' % e)
                vera_xml_root = self.run_verapdf_subprocess(vals, f)
            vals['pdfa3_engine'] = 'verapdfREST' if rest else 'verapdf subprocess'
            if vera_xml_root:
                # veraPDF-rest 1.31.x REST response now has the same
                # <report>/<jobs>/<job>/<validationReport> shape as the CLI
                # (GreenfieldCliWrapper) output, not the old
                # <vera:validationResult> namespaced format. Both paths share
                # the same parser now; `rest` still only picks HTTP vs subprocess above.
                pdfa_errors = self.analyse_verapdf_subprocess(vals, vera_xml_root)
                if pdfa_errors:
                    self.vera_errors_reformat(pdfa_errors, errors)
            else:
                errors['1_pdfa3'].append({
                    'name': 'Failure to run the PDF/A-3 test with veraPDF',
                    'comment': 'This is a technical failure of the Factur-X/Order-X validator. The problem is not linked to the PDF file you uploaded.',
                    })
            xmp_root = self.extract_xmp(vals, pdf_root, errors)

            xml_root = xml_bytes = None
            res_xml = self.extract_xml(vals, pdf_root, errors)
            if res_xml:
                xml_root, xml_bytes = res_xml
            # Set pdfa3_valid later in the code, because
            # there is a check later on AFRelationShip

        elif vals['file_type'] == 'xml':
            xml_bytes = base64.decodebytes(self.facturx_file)
            xml_root = None
            try:
                xml_root = etree.fromstring(xml_bytes)
            except Exception as e:
                errors['3_xml'].append({
                    'name': 'Not a valid XML file',
                    'comment': 'Technical error message:\n%s' % e,
                    })
        xsd_ran = False
        if xml_root:
            self.analyse_xml_xsd(vals, xml_root, errors)
            xsd_ran = True
        else:
            vals['doc_type'] = 'facturx'
            if not errors['3_xml']:
                # No XML could be extracted (e.g. a plain PDF with no embedded
                # CII, or a broken PDF catalog). XSD and Schematron cannot run;
                # record why so the report shows a reason instead of an empty
                # XML section -- and so the verdicts below are not left to
                # default to "valid" from the mere absence of errors.
                errors['3_xml'].append({
                    'name': 'No XML extracted from the file',
                    'comment': 'No Factur-X/Order-X XML could be read from the '
                               'PDF, so XSD and Schematron validation were not '
                               'run.',
                })
        # Starting from here, we have vals['doc_type'] and vals['xml_profile']
        if vals['file_type'] == 'pdf':
            if (vals.get('afrelationship') and vals['afrelationship'] != '/Data' and vals['xml_profile'
            ] in ('facturx_minimum', 'facturx_basicwl')):
                errors['1_pdfa3'].append({
                    'name': '/AFRelationship = %s not allowed for this Factur-X profile' % vals['afrelationship'],
                    'comment': "For Factur-X profiles Minimum and Basic WL, "
                               "/AFRelationship for attachment factur-x.xml must be "
                               "/Data, it cannot be /Alternative nor /Source. "
                               "In this file, /AFRelationship for attachment "
                               "factur-x.xml is %s." % vals['afrelationship']
                    })
            if xmp_root:
                self.analyse_xmp(vals, xmp_root, errors)
                if not errors['2_xmp']:
                    vals['xmp_valid'] = True
            if vals.get('xml_filename'):
                if vals['doc_type'] == 'facturx' and vals['xml_filename'] == 'order-x.xml':
                    errors['1_pdfa3'].append({
                        'name': 'Wrong XML filename',
                        'comment': "The attached XML filename is order-x.xml, but the content of the XML follows the Factur-X standard!"
                        })
                elif vals['doc_type'] == 'orderx' and vals['xml_filename'] == 'factur-x.xml':
                    errors['1_pdfa3'].append({
                        'name': 'Wrong XML filename',
                        'comment': "The attached XML filename is factur-x.xml, but the content of the XML follows the Order-X standard!"
                        })
                # Rename xml_filename for easier download
                vals['xml_filename'] = '%s-x_%s.xml' % (vals['doc_type'][:-1], self.name.replace('/', '_'))
        schematron_ran = False
        if vals.get('xml_profile') and vals['xml_profile'].startswith('facturx_') and xml_bytes:
            self.analyse_xml_schematron_facturx(vals, xml_bytes, errors, prefix)
            schematron_ran = True
        elif vals.get('xml_profile') and vals['xml_profile'].startswith('cii_') and xml_bytes:
            self.analyse_xml_schematron_cii(vals, xml_bytes, errors, prefix)
            schematron_ran = True
        elif vals.get('xml_profile') and vals['xml_profile'].startswith('orderx_') and xml_root is not None:
            self.analyse_xml_schematron_orderx(vals, xml_root, errors, prefix)
            schematron_ran = True
        elif vals.get('xml_profile') and vals['xml_profile'].startswith('ubl_') and xml_bytes:
            self.analyse_xml_schematron_ubl(vals, xml_bytes, errors, prefix)
            schematron_ran = True
        elif vals.get('xml_profile') and vals['xml_profile'] == 'cdar_ctc_fr' and xml_bytes:
            self.analyse_xml_schematron_cdar(vals, xml_bytes, errors, prefix)
            schematron_ran = True
        # Record which schematron files judged this analysis (report / GUI).
        _sch_rules = PROFILE_RULES.get(vals.get('xml_profile') or '', {})
        if schematron_ran and _sch_rules.get('schematron'):
            vals['schematron_profile_ruleset'] = os.path.basename(
                _sch_rules['schematron'])
        if (schematron_ran and self.br_fr_check
                and _sch_rules.get('br_fr_schematron')):
            vals['schematron_br_fr_ruleset'] = os.path.basename(
                _sch_rules['br_fr_schematron'])
        # A verdict may only be set to valid when its stage actually ran. If no
        # XML could be extracted, or the profile could not be read, XSD and
        # Schematron never execute and their error groups stay empty -- that
        # absence of errors must NOT be reported as a pass.
        if xsd_ran and not errors['3_xml']:
            vals['xml_valid'] = True
        # A schematron pass is valid when it has no blocking (severity 'fatal')
        # entry; 'warning' entries are reported but non-blocking.
        def _blocking(err_list):
            return [e for e in err_list if e.get('severity', 'fatal') == 'fatal']
        if schematron_ran and not _blocking(errors['4_xml_schematron_profile']):
            vals['xml_schematron_profile_valid'] = True
        # "France" toggle off: the systematic BR-FR schematron (pass 2) is not
        # run at all (see analyse_xml_schematron_facturx / _cii / _ubl), so
        # group 5 stays empty and BR-FR does not enter the overall schematron
        # verdict -- xml_schematron_valid then only reflects the Profile pass.
        # When pass 1 ran but pass 2 was skipped by design (facturx_minimum, or
        # a flavour with no BR-FR pass), group 5 is legitimately empty and the
        # BR-FR verdict is a vacuous pass -- hence gated on schematron_ran, the
        # same flag as the Profile pass, not on a separate "br_fr ran" flag.
        if self.br_fr_check:
            if schematron_ran and not _blocking(errors['5_xml_schematron_br_fr']):
                vals['xml_schematron_br_fr_valid'] = True
            if vals.get('xml_schematron_profile_valid') and vals.get('xml_schematron_br_fr_valid'):
                vals['xml_schematron_valid'] = True
        else:
            vals['xml_schematron_valid'] = vals.get('xml_schematron_profile_valid', False)
        logger.info(
            'vals after schematron: xml_valid=%s xml_schematron_valid=%s valid=%s sch_errors=%d',
            vals.get('xml_valid'), vals.get('xml_schematron_valid', False),
            vals.get('valid', False), len(errors['4_xml_schematron_profile'])
            #vals.get('valid', False), len(errors['5_xml_schematronbr_br_fr'])
            #vals.get('valid', False), len(errors['6_xml_schematronbr_cpro'])
        )
        if vals['file_type'] == 'pdf':
            if not errors['1_pdfa3']:
                vals['pdfa3_valid'] = True
            if (
                    vals.get('pdfa3_valid') and
                    vals.get('xmp_valid') and
                    vals.get('xml_valid') and
                    vals.get('xml_schematron_valid') and
                    vals.get('xmp_profile') and
                    vals.get('xmp_profile') == vals.get('xml_profile') and
                    vals.get('xmp_orderx_type') == vals.get('xml_orderx_type')
                    ):
                vals['valid'] = True
        elif vals['file_type'] == 'xml':
            if vals.get('xml_valid') and vals.get('xml_schematron_valid'):
                vals['valid'] = True
        facturx_file_size = os.stat(f.name).st_size
        f.seek(0)
        facturx_file_sha1 = hashlib.sha1(f.read()).hexdigest()
        f.close()
        # logger.debug('vals at end of analysis=%s', vals)
        errors_write = self.errors2errors_write(errors)
        vals.update({
            'state': 'done',
            'date': fields.Datetime.now(),
            'facturx_file_sha1': facturx_file_sha1,
            'facturx_file_size': facturx_file_size,
            'error_ids': errors_write,
            })
        self.write(vals)
        logger.info('End analysis of %s', self.name)
        return

    def extract_xmp(self, vals, pdf_root, errors):
        try:
            metaobj = pdf_root['/Metadata']
            xmp_bytes = metaobj.get_data()
        except Exception as e:
            errors['2_xmp'].append({
                'name': 'No valid /Metadata in PDF structure',
                'comment': "Cannot extract content of /Metadata from PDF. Error: %s" % e,
                })
            return False
        vals.update({
            'xmp_file': base64.encodebytes(xmp_bytes),
            'xmp_filename': 'metadata_%s.xml' % self.name.replace('/', '_'),
            })
        xmp_root = False
        try:
            xmp_root = etree.fromstring(xmp_bytes)
        except Exception as e:
            errors['2_xmp'].append({
                'name': 'XMP Metadata file is not a valid XML file',
                'comment': 'Technical error message:\n%s' % e,
                })
        return xmp_root

    def analyse_xmp(self, vals, xmp_root, errors):
        logger.info('Start analyse_xmp (doc_type=%s)', vals.get('doc_type'))
        namespaces = {
            'x': 'adobe:ns:meta/',
            'rdf': "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
            'fx': 'urn:factur-x:pdfa:CrossIndustryDocument:invoice:1p0#',
            }
        desc_xpath_str = '/x:xmpmeta/rdf:RDF/rdf:Description'
        desc_xpath = xmp_root.xpath(
            desc_xpath_str, namespaces=namespaces)
        if not desc_xpath:
            errors['2_xmp'].append({
                'name': 'Required tag missing in XMP Metadata',
                'comment': 'Missing path /x:xmpmeta/rdf:RDF/rdf:Description '
                           'in XMP Metadata',
                })
            return
        if vals['doc_type'] == 'orderx':
            tags = {
                'DocumentType': [x[0].upper() for x in ORDERX_TYPES],
                'DocumentFileName': [ORDERX_FILENAME],
                'Version': ['1.0'],
                'ConformanceLevel': list(ORDERX_xmp2level.keys()),
                }
            xmp2level = ORDERX_xmp2level
            namespaces['fx'] = 'urn:factur-x:pdfa:CrossIndustryDocument:1p0#'
        else:
            tags = {
                'DocumentType': ['INVOICE'],
                'DocumentFileName': [FACTURX_FILENAME],
                'Version': ['1.0'],
                'ConformanceLevel': list(FACTURX_xmp2level.keys()),
                }
            xmp2level = FACTURX_xmp2level
        res = {}
        for desc_node in desc_xpath:
            for tag_name in tags.keys():
                # First, check attributes
                attrib_key = '{%s}%s' % (namespaces['fx'], tag_name)
                if desc_node.attrib and attrib_key in desc_node.attrib:
                    res[tag_name] = desc_node.attrib[attrib_key]
                # then check sub-tags
                else:
                    xpath_str = '%s/fx:%s' % (desc_xpath_str, tag_name)
                    tag_xpath = xmp_root.xpath(xpath_str, namespaces=namespaces)
                    if tag_xpath and tag_xpath[0].text:
                        res[tag_name] = tag_xpath[0].text.strip()
        for tag_name, tag_val in tags.items():
            xpath_str = '%s/fx:%s' % (desc_xpath_str, tag_name)
            if tag_name not in res:
                errors['2_xmp'].append({
                    'name': "Required tag '%s' missing" % tag_name,
                    'comment': "Missing tag %s in XMP Metadata "
                               "(can also be set via an attribute '%s' of "
                               "the tag '%s')" % (
                                   xpath_str, tag_name, desc_xpath_str),
                    })
            elif res.get(tag_name) not in tags[tag_name]:
                errors['2_xmp'].append({
                    'name': "Wrong value for tag '%s'" % tag_name,
                    'comment': "For tag '%s' (or attribute '%s' of tag '%s'), the value is '%s' whereas the value should be %s" % (xpath_str, tag_name, desc_xpath_str, res.get(tag_name), ' or '.join([f"'{x}'" for x in tags[tag_name]])),
                    })
            elif vals['doc_type'] == 'orderx' and tag_name == 'DocumentType':
                vals['xmp_orderx_type'] = res[tag_name].lower()
            elif tag_name == 'ConformanceLevel':
                vals['xmp_profile'] = xmp2level[res[tag_name]]
        return

    def _get_dict_entry(self, node, entry):
        logger.debug('_get_dict_entry: entry=%s', entry)
        if not isinstance(node, dict):
            raise ValueError('The node must be a dict')
        dict_entry = node.get(entry)
        if isinstance(dict_entry, dict):
            return dict_entry
        elif isinstance(dict_entry, IndirectObject):
            res_dict_entry = dict_entry.get_object()
            if isinstance(res_dict_entry, dict):
                return res_dict_entry
            else:
                return False
        else:
            return False

    def _parse_embeddedfiles_kids_node(self, kids_node, level, res):
        if level not in [1, 2]:
            raise ValueError('Level argument should be 1 or 2')
        # The /Kids entry of the EmbeddedFiles name tree must be an array
        if not isinstance(kids_node, list):
            return False
        for kid_entry in kids_node:
            # The /Kids entry of the EmbeddedFiles name tree must be a
            # list of IndirectObjects
            if not isinstance(kid_entry, IndirectObject):
                return False
            kids_node = kid_entry.get_object()
            # The /Kids entry of the EmbeddedFiles name tree
            # must be a list of IndirectObjects that point to dict objects
            if not isinstance(kids_node, dict):
                return False
            if '/Names' in kids_node:
                # The /Names entry in EmbeddedFiles must be an array
                if not isinstance(kids_node['/Names'], list):
                    return False
                res += kids_node['/Names']
            elif '/Kids' in kids_node and level == 1:
                kids_node_l2 = kids_node['/Kids']
                self._parse_embeddedfiles_kids_node(kids_node_l2, 2, res)
            else:
                # /Kids node should have a /Names or /Kids entry
                return False
        return True

    def _get_embeddedfiles(self, embeddedfiles_node):
        if not isinstance(embeddedfiles_node, dict):
            raise ValueError('The EmbeddedFiles node must be a dict')
        res = []
        if '/Names' in embeddedfiles_node:
            # The /Names entry of the EmbeddedFiles name tree must be an array
            if not isinstance(embeddedfiles_node['/Names'], list):
                return False
            res = embeddedfiles_node['/Names']
        elif '/Kids' in embeddedfiles_node:
            kids_node = embeddedfiles_node['/Kids']
            parse_result = self._parse_embeddedfiles_kids_node(
                kids_node, 1, res)
            if parse_result is False:
                return False
        else:
            # The EmbeddedFiles name tree should have either a /Names or a
            # /Kids entry
            return False
        # The EmbeddedFiles name tree should point to an even number
        # of elements
        if len(res) % 2 != 0:
            return False
        return res

    def extract_xml(self, vals, pdf_root, errors):
        logger.info('Start extract_xml')
        xml_root = xml_string = None
        try:
            catalog_name = self._get_dict_entry(pdf_root, '/Names')
        except Exception:
            errors['1_pdfa3'].append({
                'name': 'Missing /Names in PDF Catalog',
                })
            return False
        try:
            embeddedfiles_node = self._get_dict_entry(
                catalog_name, '/EmbeddedFiles')
        except Exception:
            errors['1_pdfa3'].append({
                'name': 'Missing /Names/EmbeddedFiles in PDF Catalog',
                })
            return False
        if not embeddedfiles_node:
            errors['1_pdfa3'].append({
                'name': 'Missing /Names/EmbeddedFiles in PDF Catalog',
                })
            return False
        embeddedfiles = self._get_embeddedfiles(embeddedfiles_node)
        if not embeddedfiles:
            errors['1_pdfa3'].append({
                'name': 'Missing /Names/EmbeddedFiles/Names or '
                        '/Names/EmbeddedFiles/Kids in PDF Catalog '
                        'or wrong structure',
                })
            return False
        # embeddedfiles must contain an even number of elements
        embeddedfiles_by_two = list(zip(embeddedfiles, embeddedfiles[1:]))[::2]
        logger.debug('embeddedfiles_by_two=%s', embeddedfiles_by_two)
        facturx_file_present = False
        other_filenames = []
        for (filename, file_obj) in embeddedfiles_by_two:
            if filename not in ALL_FILENAMES:
                other_filenames.append(filename)
            else:
                try:
                    xml_file_dict = file_obj.get_object()
                except Exception:
                    errors['1_pdfa3'].append({
                        'name': 'Unable to get the PDF file object %s' % filename,
                        })
                    continue
                if '/Type' not in xml_file_dict:
                    errors['1_pdfa3'].append({
                        'name': 'Missing entry /Type in File Specification Dictionary',
                        })
                elif xml_file_dict.get('/Type') != '/Filespec':
                    errors['1_pdfa3'].append({
                        'name': 'Wrong value for /Type in File Specification Dictionary',
                        'comment': "Value for /Type in File Specification "
                                   "Dictionary should be '/Filespec'. "
                                   "Current value is '%s'." % xml_file_dict.get('/Type')
                        })
                # presence of /F and /UF already checked by VeraPDF
                for entry in ['/F', '/UF']:
                    if xml_file_dict.get(entry) not in ALL_FILENAMES:
                        errors['1_pdfa3'].append({
                            'name': 'Wrong value for %s in File Specification Dictionary' % entry,
                            'comment': "Value for %s in File Specification "
                                       "Dictionary should be 'factur-x.xml'. "
                                       "Current value is '%s'." % (entry, xml_file_dict.get(entry))
                            })

                afrel_accepted = ['/Data', '/Source', '/Alternative']
                vals['afrelationship'] = xml_file_dict.get('/AFRelationship')
                # If '/AFRelationship' not in xml_file_dict, it is reported by veraPDF
                if (
                        xml_file_dict.get('/AFRelationship') and
                        xml_file_dict['/AFRelationship'] not in afrel_accepted):
                    errors['1_pdfa3'].append({
                        'name': 'Wrong value for /AFRelationship for file %s' % filename,
                        'comment': "Accepted values for /AFRelationship are: %s. "
                                   "Current value is '%s'." % (
                                       ', '.join(["'%s'" % x for x in afrel_accepted]),
                                       xml_file_dict.get('/AFRelationship', '')),
                        })

                try:
                    xml_string = xml_file_dict['/EF']['/F'].get_data()
                    xml_file_subdict = xml_file_dict['/EF']['/F'].get_object()
                except Exception:
                    errors['1_pdfa3'].append({
                        'name': 'Unable to extract the file %s' % filename,
                        'comment': 'Wrong value for /EF/F for file %s' % filename,
                        })
                    continue
                # The absence of /Subtype is reported by veraPDF
                # pypdf now reports '/text/xml' (PyPDF4 reported /text#2fxml)
                if (
                        xml_file_subdict.get('/Subtype') and
                        xml_file_subdict['/Subtype'] not in ['/text#2Fxml', '/text#2fxml', '/text/xml']):
                    errors['1_pdfa3'].append({
                        'name': 'Wrong value for /EF/F/Subtype',
                        'comment': "Value for /EF/F/Subtype should be '/text/xml'. "
                                   "Current value is '%s'." % xml_file_subdict.get('/Subtype')
                        })
                if '/Type' not in xml_file_subdict:
                    errors['1_pdfa3'].append({
                        'name': 'Missing entry /EF/F/Type',
                        })
                elif xml_file_subdict.get('/Type') != '/EmbeddedFile':
                    errors['1_pdfa3'].append({
                        'name': 'Wrong value for /EF/F/Type',
                        'comment': "Value for /EF/F/Type should be '/EmbeddedFile'. "
                                   "Current value is '%s'." % xml_file_subdict.get('/Type')
                        })
                facturx_file_present = True
                try:
                    xml_root = etree.fromstring(xml_string)
                except Exception as e:
                    errors['3_xml'].append({
                        'name': 'The Factur-x/Order-X XML file is not a valid XML file',
                        'comment': 'Technical error message:\n%s' % e,
                        })
                    continue
                vals['xml_file'] = base64.encodebytes(xml_string)
                # in vals['xml_filename'] we store the original filename
                # and, later in the code, we use it to see if it's coherent with
                # the doc_type, and then we rename it for easier download
                vals['xml_filename'] = filename

        if not facturx_file_present:
            other_filenames_label = other_filenames and ', '.join([f"'{x}'" for x in other_filenames]) or 'none'
            errors['3_xml'].append({
                'name': "No embedded 'factur-x.xml' nor 'order-x.xml' file.",
                "comment": f"List of filenames found in /Names/EmbeddedFiles/Names: {other_filenames_label}. Look at the diagram at the end of section 6.2 of the Factur-X specification to implement correctly the integration of the XML file in the PDF."
                })
        return xml_root, xml_string

    def analyse_xml_xsd(self, vals, xml_root, errors):
        logger.info('Start analyse_xml_xsd')
        flavor = get_flavor(xml_root)
        logger.info('analyse_xml_xsd: flavor=%s', flavor)
        if flavor == 'ubl':
            vals['doc_type'] = 'ubl'
            cbc_ns = 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'
            cid_nodes = xml_root.xpath(
                'cbc:CustomizationID',
                namespaces={'cbc': cbc_ns})
            cid = (cid_nodes[0].text or '').strip() if cid_nodes else ''
            if not cid:
                errors['3_xml'].append({
                    'name': 'Missing cbc:CustomizationID',
                    'comment': 'A UBL invoice must carry a CustomizationID (BT-24 / BR-01).',
                    })
                return
            ubl_profile = None
            for prefix, profile in UBL_PROFILE_MAP:
                if cid == prefix:
                    ubl_profile = profile
                    break
            if not ubl_profile:
                errors['3_xml'].append({
                    'name': 'Unrecognized UBL CustomizationID',
                    'comment': "CustomizationID '%s' does not match any known UBL profile." % cid,
                    })
                return
            vals['xml_profile'] = ubl_profile
            xsd_rel = (
                'facturx_validator/France_RFE/FNFE_RFE_INVOICE/UBL/1xsd_UBL2.1/maindoc/UBL-CreditNote-2.1.xsd'
                if 'CreditNote' in xml_root.tag else
                'facturx_validator/France_RFE/FNFE_RFE_INVOICE/UBL/1xsd_UBL2.1/maindoc/UBL-Invoice-2.1.xsd'
            )
            vals['xsd_ruleset'] = os.path.basename(xsd_rel)
            try:
                xsd_doc = etree.parse(file_path(xsd_rel))
                etree.XMLSchema(xsd_doc).assertValid(xml_root)
            except Exception as e:
                errors['3_xml'].append({
                    'name': 'XML file invalid against UBL 2.1 XSD',
                    'comment': '%s' % e,
                })
            return
        elif flavor == 'cdar':
            vals['doc_type'] = 'cdar'
            vals['xml_profile'] = 'cdar_ctc_fr'
            xsd_rel = 'facturx_validator/France_RFE/FNFE_RFE_INVOICE/CDAR/1xsd-CDAR_D22B_uncoupled/CrossDomainAcknowledgementAndResponse_100pD22B.xsd'
            vals['xsd_ruleset'] = os.path.basename(xsd_rel)
            try:
                xsd_doc = etree.parse(file_path(xsd_rel))
                etree.XMLSchema(xsd_doc).assertValid(xml_root)
            except Exception as e:
                errors['3_xml'].append({
                    'name': 'XML file invalid against CDAR XSD',
                    'comment': '%s' % e,
                })
            return
        elif flavor == 'factur-x':
            vals['doc_type'] = 'facturx' if vals.get('file_type') == 'pdf' else 'cii'
            namespaces = FACTURX_XML_FX_NAMESPACES
        elif flavor == 'order-x':
            vals['doc_type'] = 'orderx'
            namespaces = ORDERX_XML_NAMESPACES
            try:
                vals['xml_orderx_type'] = get_orderx_type(xml_root).lower()
            except Exception as e:
                errors['3_xml'].append({
                    'name': 'Invalid Order-X Type Code',
                    'comment': '%s' % e,
                    })
        else:
            errors['3_xml'].append({
                'name': 'Neither Order-X nor Factur-X file',
                'comment': 'Unrecognized document format (not Factur-X, Order-X, UBL, CDAR, nor e-Reporting).',
            })
            return
        # Check profile
        doc_id_xpath = xml_root.xpath(
            "//rsm:ExchangedDocumentContext"
            "/ram:GuidelineSpecifiedDocumentContextParameter"
            "/ram:ID", namespaces=namespaces)
        if not doc_id_xpath:
            errors['3_xml'].append({
                'name': 'Missing tag in XML file',
                'comment': "Missing XML tag ExchangedDocumentContext/"
                "GuidelineSpecifiedDocumentContextParameter/ID, so we "
                "cannot read the profile and therefore we cannot test "
                "against the XSD.",
                })
            return
        doc_id = doc_id_xpath[0].text
        if not doc_id:
            errors['3_xml'].append({
                'name': 'Empty tag in XML file',
                'comment': "The tag ExchangedDocumentContext/"
                "GuidelineSpecifiedDocumentContextParameter/ID "
                "is empty, so we cannot read the profile and "
                "therefore we cannot test against the XSD.",
                })
            return
        # An explicit factur-x.eu / cpro.gouv.fr marker in the guideline URN
        # tells Factur-X from native CII even for a standalone XML upload --
        # get_flavor() can't, they share the root namespace. Only the bare
        # 'urn:cen.eu:en16931:2017' is not in the map and keeps the file_type
        # guess made above (pdf -> facturx, xml -> cii).
        mapped_profile = GUIDELINE_PROFILE_MAP.get((doc_id or '').strip())
        if mapped_profile:
            xml_profile = mapped_profile
            vals['doc_type'] = xml_profile.split('_')[0]
        else:
            doc_id_split = doc_id.split(':')
            xml_profile = '%s_%s' % (vals['doc_type'], doc_id_split[-1])
            PROFILES_LIST = [x[0] for x in PROFILES]
            if xml_profile not in PROFILES_LIST and len(doc_id_split) > 1:
                xml_profile = '%s_%s' % (vals['doc_type'], doc_id.split(':')[-2])
            if xml_profile not in PROFILES_LIST:
                errors['3_xml'].append({
                    'name': "Invalid URN",
                    'comment': "Invalid URN '%s' in the XML tag "
                               "ExchangedDocumentContext/"
                               "GuidelineSpecifiedDocumentContextParameter/ID" % doc_id,
                    })
                return
        vals['xml_profile'] = xml_profile
        logger.info('analyse_xml_xsd: profile=%s', xml_profile)
        # Validate against the FNFE France_RFE schema when the profile ships one
        # (Factur-X = per-profile restricted subset; CII / CDAR = the full,
        # unrestricted D22B schema). The legacy Factur-X profiles (minimum,
        # basic) have no repo XSD -> fall back to the `facturx` library's
        # bundled schema. Standalone CII was previously forced through the
        # library at level 'extended-ctc-fr' to dodge the restricted subsets;
        # with the full D22B repo XSD that hack is no longer needed.
        xsd_rel = PROFILE_RULES.get(xml_profile, {}).get('xsd')
        try:
            if xsd_rel:
                vals['xsd_ruleset'] = os.path.basename(xsd_rel)
                xsd_doc = etree.parse(file_path(xsd_rel))
                etree.XMLSchema(xsd_doc).assertValid(xml_root)
            else:
                vals['xsd_ruleset'] = 'facturx library'
                xml_check_xsd(
                    xml_root, flavor=flavor, level=xml_profile.split('_')[1])
        except Exception as e:
            errors['3_xml'].append({
                'name': 'XML file invalid against XSD',
                'comment': '%s' % e,
            })
        return

    @api.model
    def _config_parameter_filepath_update(self, paths):
        assert isinstance(paths, dict)
        ico = self.env['ir.config_parameter'].sudo()
        for key in paths:
            paths[key] = ico.get_param(key)
            if not paths[key]:
                raise UserError(_(
                    "Missing system parameter '%s' "
                    "or empty value for this parameter.") % key)
            if not os.path.isfile(paths[key]):
                raise UserError(_(
                    "File '%s' stated in system parameter '%s' "
                    "doesn't exist on the Odoo server filesystem.")
                    % (paths[key], key))

    def analyse_xml_schematron_orderx(self, vals, xml_root, errors, prefix=None):
        logger.info('Start analyse_xml_schematron_orderx (profile=%s)', vals.get('xml_profile'))
        # As the SCH of Order-X are ISO SCH and not XSTL2, we can use lxml
        if not vals['xml_profile'].startswith('orderx_'):
            raise UserError(_("Wrong XML profile %s. Must be an Order-X profile. This should never happen.") % vals['xml_profile'])
        sch_relative_path = PROFILE_RULES[vals['xml_profile']]['schematron']
        with file_open(sch_relative_path, 'rb') as f:
            sch_bytes = f.read()
        try:
            sch_root = etree.fromstring(sch_bytes)
        except Exception as e:
            raise UserError(_(
                "Cannot parse SCH XML file %s. Error: %s") % (sch_relative_path, e))
        schematron = Schematron(sch_root, store_report=True)
        res = schematron.validate(xml_root)
        logger.debug('analyse_xml_schematron_orderx res=%s', res)
        svrl_xml_string = schematron.validation_report
        logger.debug('orderx svrl_xml_string=%s', svrl_xml_string)
        svrl_root = etree.fromstring(str(svrl_xml_string))
        if res is False:
            logger.info('file is invalid according to Schematron')
            self.schematron_result_analysis(vals, svrl_root, errors)
        else:
            logger.info('file is valid according to Schematron')

    def _run_schematron_saxon(self, vals, xml_bytes, errors, stylesheet_rel, prefix=None, group='4_xml_schematron_profile'):
        if not stylesheet_rel:
            errors[group].append({
                'name': 'Schematron validation not available for profile %s'
                        % vals.get('xml_profile'),
                'comment': 'No compiled XSLT stylesheet is configured for this '
                           'profile in PROFILE_RULES.',
                })
            return
        stylesheet_file = file_path(stylesheet_rel)
        logger.info('Start schematron validation (saxon): %s', stylesheet_rel)
        logger.debug('stylesheet_file absolute path=%s', stylesheet_file)
        with NamedTemporaryFile('wb+', prefix=prefix, suffix='.xml') as xml_file:
            xml_file.write(xml_bytes)
            xml_file.seek(0)
            with saxonche.PySaxonProcessor(license=False) as saxproc:
                logger.debug('saxon version %s', saxproc.version)
                xslt_processor = saxproc.new_xslt30_processor()
                result_str = xslt_processor.transform_to_string(
                    source_file=xml_file.name, stylesheet_file=stylesheet_file)
                svrl_root = etree.fromstring(result_str.encode('utf-8'))
                self.schematron_result_analysis(vals, svrl_root, errors, group=group)
        logger.info('End schematron validation (saxon): %s', stylesheet_rel)

    def _analyse_xml_schematron_saxon(self, vals, xml_bytes, errors, prefix=None):
        """Profile schematron (pass 1, group 4) then the systematic BR-FR
        schematron (pass 2, group 5) -- the latter only when the "France"
        toggle is on and PROFILE_RULES ships a BR-FR ruleset for this profile
        (legacy Factur-X minimum/basic don't). Shared by the Factur-X, CII and
        UBL entry points, which now differ only by their profile-prefix guard.
        """
        rules = PROFILE_RULES.get(vals['xml_profile'], {})
        logger.info('Schematron pass 1 (profile=%s)', vals['xml_profile'])
        self._run_schematron_saxon(
            vals, xml_bytes, errors, rules.get('schematron_xslt'), prefix)
        logger.info('Pass 1 done: %d in 4_xml_schematron_profile',
                    len(errors.get('4_xml_schematron_profile', [])))
        if self.br_fr_check and rules.get('br_fr_schematron_xslt'):
            logger.info('Schematron pass 2 (BR-FR)')
            self._run_schematron_saxon(
                vals, xml_bytes, errors, rules['br_fr_schematron_xslt'],
                prefix, group='5_xml_schematron_br_fr')
            logger.info('Pass 2 done: %d in 5_xml_schematron_br_fr',
                        len(errors.get('5_xml_schematron_br_fr', [])))
        elif not self.br_fr_check:
            logger.info('Schematron pass 2 skipped ("France" toggle off)')

    def analyse_xml_schematron_facturx(self, vals, xml_bytes, errors, prefix=None):
        if not vals['xml_profile'].startswith('facturx_'):
            raise UserError(_("Wrong XML profile %s. Must be a Factur-X profile. This should never happen.") % vals['xml_profile'])
        self._analyse_xml_schematron_saxon(vals, xml_bytes, errors, prefix)

    def analyse_xml_schematron_cii(self, vals, xml_bytes, errors, prefix=None):
        if not vals['xml_profile'].startswith('cii_'):
            raise UserError(_("Wrong XML profile %s. Must be a CII profile. This should never happen.") % vals['xml_profile'])
        self._analyse_xml_schematron_saxon(vals, xml_bytes, errors, prefix)

    def analyse_xml_schematron_ubl(self, vals, xml_bytes, errors, prefix=None):
        if not vals['xml_profile'].startswith('ubl_'):
            raise UserError(_("Wrong XML profile %s. Must be a UBL profile. This should never happen.") % vals['xml_profile'])
        self._analyse_xml_schematron_saxon(vals, xml_bytes, errors, prefix)

    def analyse_xml_schematron_cdar(self, vals, xml_bytes, errors, prefix=None):
        if vals['xml_profile'] != 'cdar_ctc_fr':
            raise UserError(_("Wrong XML profile %s. Must be cdar_ctc_fr. This should never happen.") % vals['xml_profile'])
        # CDAR: the single BR-FR-CDV ruleset IS the whole schematron -- one
        # pass into group 4, no separate BR-FR pass.
        rules = PROFILE_RULES.get(vals['xml_profile'], {})
        self._run_schematron_saxon(
            vals, xml_bytes, errors, rules.get('schematron_xslt'), prefix)
        logger.info('End analyse_xml_schematron_cdar: sch_errors=%d',
                    len(errors.get('4_xml_schematron_profile', [])))

    def schematron_result_analysis(self, vals, svrl_root, errors, group='4_xml_schematron_profile'):
        logger.info('Start schematron_result_analysis')
        namespaces = svrl_root.nsmap
        sch_errors = svrl_root.xpath(
            ".//svrl:successful-report | .//svrl:failed-assert",
            namespaces=namespaces)
        logger.info('schematron_result_analysis: %d error(s) found', len(sch_errors))
        for sch_error in sch_errors:
            # 'failed-assert' or 'successful-report'
            localname = etree.QName(sch_error).localname
            detail_xpath = sch_error.xpath("*[local-name() = 'text']", namespaces=namespaces)
            if detail_xpath:
                comment = detail_xpath[0].text and detail_xpath[0].text.strip()
                location = sch_error.attrib and sch_error.attrib.get('location')
                if location:
                    comment += '\nLocation of the error: %s' % location
                if comment:
                    # severity is the SVRL @flag verbatim (lowercased) -- the
                    # schematron declares it per rule and that is the only
                    # source of truth. A missing/empty flag means 'fatal';
                    # 'info'/'information' rows are dropped (noise, never affect
                    # validity). In practice the profile pass emits 'fatal' +
                    # 'warning', the BR-FR pass only 'fatal'. Nothing else is
                    # consulted -- not the assertion kind, not the "France"
                    # toggle.
                    flag = (sch_error.attrib.get('flag') or '').strip().lower()
                    if flag in ('info', 'information'):
                        continue
                    severity = 'warning' if flag == 'warning' else 'fatal'
                    # Saxon output has an 'id' attrib (the rule id); the lxml
                    # path for Order-X has none.
                    rule_id = sch_error.attrib.get('id') or ''
                    # svrl:text always repeats the id as a "[BR-CO-09]-" prefix;
                    # keep it as-is (the printed report renders it in bold).
                    # name = the assertion kind (failed-assert / successful-report),
                    # test_condition = its "when"/@test xpath (the condition that
                    # must hold for the assertion to pass).
                    errors[group].append({
                        'name': localname or "Schematron error",
                        'comment': comment,
                        'severity': severity,
                        'rule_id': rule_id or False,
                        'test_condition': sch_error.attrib.get('test') or False,
                        })

    def run_verapdf_rest(self, vals, f):
        logger.info('Start run_verapdf_rest for %s', self.name)
        f.seek(0)  # VERY IMPORTANT !!!
        ico = self.env['ir.config_parameter'].sudo()
        url = ico.get_param('facturx.verapdf.rest.url')
        if not url:
            raise UserError(_(
                "Missing system parameter 'facturx.verapdf.rest.url' "
                "or empty value for this parameter."))
        files = {'file': f}
        headers = {'Accept': 'application/xml'}
        res_request = requests.post(url, files=files, headers=headers)
        if res_request.status_code != 200:
            logger.error(
                "The request to %s returned HTTP code %d",
                url, res_request.status_code)
            raise UserError(_(
                "Failed to work with veraPDF via REST"))
        xml_string = res_request.text
        # fr = open('/tmp/answer_veraPDF_rest.xml', 'w')
        # fr.write(xml_string)
        # fr.close()
        vera_xml_root = ET.fromstring(xml_string.encode('utf8'))
        return vera_xml_root

    def run_verapdf_subprocess(self, vals, f):
        ico = self.env['ir.config_parameter'].sudo()
        classpath = ico.get_param('facturx.verapdf.classpath')
        if not classpath:
            raise UserError(_(
                "Missing system parameter 'facturx.verapdf.classpath' "
                "or empty value for this parameter."))
        cmd_list = [
            '/usr/bin/java',
            '-Xmx512m',
            '-XX:ReservedCodeCacheSize=32m',
            '-XX:TieredStopAtLevel=1',
            '-classpath',
            classpath,
            #  '-Dfile.encoding=UTF8',  # MARCHE
            #  '-XX:+IgnoreUnrecognizedVMOptions',
            #  '-Dapp.name="VeraPDF validation CLI"',
            #  '-Dapp.repo="/opt/verapdf/bin"',
            #  '-Dapp.home="/opt/verapdf"',
            #  '-Dbasedir="/opt/verapdf"',
            'org.verapdf.apps.GreenfieldCliWrapper',
            f.name,
            ]
        logger.info('Start to spawn veraPDF for %s', self.name)
        logger.info('veraPDF command: %s', cmd_list)
        process = subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False)
        out, err = process.communicate()
        if err:
            logger.error('Error output in subprocess call: %s', err)
        logger.info('subprocess out=%s', out)
        logger.info('End veraPDF for %s', self.name)
        try:
            vera_xml_root = ET.fromstring(out)
        except Exception as e:
            logger.warning('Failed to parse output of veraPDF cmd line as XML file. Error: %s', e)
            vera_xml_root = False
        return vera_xml_root

    def analyse_verapdf_rest(self, vals, vera_xml_root):
        errors = []
        namespaces = {'vera': 'http://www.verapdf.org/ValidationProfile'}
        result_xpath = vera_xml_root.xpath(
            '/vera:validationResult', namespaces=namespaces)
        profile = result_xpath and result_xpath[0].attrib.get('flavour') or False
        compliant = result_xpath and result_xpath[0].attrib.get('isCompliant') or False
        logger.info(
            'Analysis %s: profile=%s compliant=%s',
            self.name, profile, compliant)
        if compliant not in ('true', 'false'):
            raise UserError(_(
                "Bad output of Rest veraPDF: compliant=%s" % compliant))
        if compliant == 'true':
            if not profile.startswith('PDFA_3'):
                errors.append({
                    'name': 'PDF profile is not PDF/A-3',
                    'comment': "PDF profile is '%s'" % profile,
                    })
        errors_xpath = vera_xml_root.xpath(
            "/vera:validationResult/vera:assertions/vera:assertion",
            namespaces=namespaces)
        tmp_errors = {}
        for verrors in errors_xpath:
            rule_xpath = verrors.xpath('vera:ruleId', namespaces=namespaces)
            spec = rule_xpath and rule_xpath[0].attrib.get('specification') or False
            clause = rule_xpath and rule_xpath[0].attrib.get('clause') or False
            test_number = rule_xpath and rule_xpath[0].attrib.get('testNumber') or False
            status = verrors.attrib.get('status') or False
            if status != 'FAILED':
                raise UserError(_(
                    "Wrong Rest XML output: STATUS = %s (should be FAILED)")
                    % status)
            msg_xpath = verrors.xpath('vera:message', namespaces=namespaces)
            msg = msg_xpath and msg_xpath[0].text or False
            if msg:
                msg = re.sub('\s+', ' ', msg)
            level_xpath = verrors.xpath(
                'vera:location/vera:level', namespaces=namespaces)
            level = level_xpath and level_xpath[0].text or False
            vcontext_xpath = verrors.xpath(
                'vera:location/vera:context', namespaces=namespaces)
            vcontext = vcontext_xpath and vcontext_xpath[0].text or False
            key = (spec, clause, test_number, msg, level)
            if key in tmp_errors:
                tmp_errors[key] += '\n' + vcontext
            else:
                tmp_errors[key] = vcontext
        for key, vcontext in tmp_errors.items():
            errors.append({
                'spec': key[0],
                'clause': key[1],
                'test_number': key[2],
                'msg': key[3],
                'level': key[4],
                'vcontext': vcontext,
                })
        return errors

    def analyse_verapdf_subprocess(self, vals, vera_xml_root):
        errors = []
        namespaces = vera_xml_root.nsmap
        result_xpath = vera_xml_root.xpath(
            '/report/jobs/job/validationReport', namespaces=namespaces)
        result_attrib = result_xpath[0].attrib
        compliant = result_attrib.get('isCompliant')
        profile = result_attrib.get('profileName')
        logger.info(
            'Analysis %s: profile=%s compliant=%s',
            self.name, profile, compliant)
        if compliant not in ('true', 'false'):
            raise UserError(_(
                "Bad output of veraPDF: isCompliant=%s" % compliant))
        if compliant == 'true':
            if not profile.startswith('PDF/A-3'):
                errors.append({
                    'name': 'PDF profile is not PDF/A-3',
                    'comment': "PDF profile is '%s'" % profile,
                    })
        errors_xpath = vera_xml_root.xpath(
            "/report/jobs/job/validationReport/details/rule[@status='failed']",
            namespaces=namespaces)
        for verrors in errors_xpath:
            spec = verrors.attrib.get('specification')
            clause = verrors.attrib.get('clause')
            test_number = verrors.attrib.get('testNumber')
            rcontext = []
            for rcheck in verrors.xpath("check[@status='failed']", namespaces=namespaces):
                rctx = rcheck.xpath('context', namespaces=namespaces)[0].text
                rcontext.append(rctx)
            msg = verrors.xpath('description', namespaces=namespaces)[0].text
            if msg:
                # Remove tab, newlines, double whitespace
                msg = re.sub('\s+', ' ', msg)
            level = verrors.xpath('object', namespaces=namespaces)[0].text
            vcontext = '\n'.join(rcontext)
            errors.append({
                'spec': spec,
                'clause': clause,
                'test_number': test_number,
                'msg': msg,
                'level': level,
                'vcontext': vcontext,

                })
        return errors

    def vera_errors_reformat(self, verrors, errors):
        for err in verrors:
            name = _('Spec. %s clause %s test %s') % (
                err.get('spec'), err.get('clause'), err.get('test_number'))
            vcontext = err.get('vcontext')
            if vcontext:
                vctx_split = vcontext.split('\n')
                if len(vctx_split) > 5:
                    vctx_split = vctx_split[:5] + ['...']
                vcontext = '\n'.join(vctx_split)
            comment = '%s\nLevel: %s\nContext:\n%s' % (
                err.get('msg'), err.get('level'), vcontext)
            errors['1_pdfa3'].append({
                'name': name,
                'comment': comment,
                })

    def print_report(self):
        self.ensure_one()
        action = self.env.ref('facturx_validator.facturx_analysis_report').with_context({'discard_logo_check': True}).report_action(self)
        return action

    def report_get_errors(self):
        self.ensure_one()
        faeo = self.env['facturx.analysis.error']
        group2label = dict(faeo.fields_get('error_group', 'selection')['error_group']['selection'])
        res = defaultdict(list)
        for err in self.error_ids:
            comment = err.comment or ''
            if err.error_group in SCHEMATRON_GROUPS:
                # PDF heading = the [fatal]/[warning] token + rule id. The token
                # is a coloured literal in the py3o template (report/analysis.odt,
                # styles Tsevfatal / Tsevwarn); only the rule id comes from here.
                name = err.rule_id or ''
                # test_condition ("When"/@test) is passed through untouched and
                # printed as its own italic line above the comment by the py3o
                # template, so it is NOT prepended here.
            else:
                name = err.name or ''
            res[group2label[err.error_group]].append({
                'name': name,
                'comment': comment,
                'severity': err.severity,
                'rule_id': err.rule_id,
                'test_condition': err.test_condition,
                # Only the schematron sections colour their heading by
                # severity in the PDF (report/analysis.odt); the other
                # sections are always 'fatal' and keep the plain style.
                'is_schematron': err.error_group in SCHEMATRON_GROUPS,
            })
        return res

class FacturxAnalysisError(models.Model):
    _name = 'facturx.analysis.error'
    _description = 'Factur-X Analysis Errors'
    # 'fatal' sorts before 'warning', so blocking rows list first
    _order = 'parent_id, error_group, severity, id'
    parent_id = fields.Many2one('facturx.analysis', ondelete='cascade')
    # It's/odoo/external-src/France_RFE to name that field 'group' because
    # it's a special word in SQL
    # These labels double as the section headers of the printed report
    # (report_get_errors -> group2label), so they must match the form-view
    # separators one-for-one. "Messages" (not "Errors") for the schematron
    # groups because those can carry non-blocking 'warning' rows too.
    error_group = fields.Selection([
        ('1_pdfa3', 'PDF/A-3 Errors'),
        ('2_xmp', 'XMP Errors'),
        ('3_xml', 'XML XSD Errors'),
        ('4_xml_schematron_profile', 'XML Schematron Profile Messages'),
        ('5_xml_schematron_br_fr', 'XML Schematron BR-FR Messages')
#        ('6_xml_schematron_cpro', 'XML Schematron CPRO Messages')
    ], string='Group', required=True)
    name = fields.Char(required=True)
    comment = fields.Text()
    # The SVRL @flag verbatim. The profile schematron emits 'fatal' + 'warning',
    # the systematic BR-FR schematron only 'fatal'; 'info'/'information' rows
    # are dropped before storage. Displayed as [fatal] / [warning] in the GUI
    # badge and the PDF heading. Only 'fatal' is blocking.
    severity = fields.Selection([
        ('fatal', '[fatal]'),
        ('warning', '[warning]'),
    ], string='Severity', required=True, default='fatal', index=True)
    rule_id = fields.Char(
        string='Rule ID',
        help="Schematron rule id (svrl @id), e.g. BR-FXEXT-AE-08ini, "
             "when available.")
    test_condition = fields.Char(
        string='When',
        help="The assertion's 'when'/@test condition: the xpath that must "
             "hold true for the schematron rule to pass.")
