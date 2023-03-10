# Copyright 2018-2021 Akretion France (https://www.akretion.com/)
# @author: Alexis de Lattre <alexis.delattre@akretion.com>

from odoo import api, fields, models, _
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
from collections import defaultdict
from PyPDF4 import PdfFileReader
from PyPDF4.generic import IndirectObject
from facturx import xml_check_xsd, get_flavor, get_orderx_type
import logging
logger = logging.getLogger(__name__)

FACTURX_FILENAME = 'factur-x.xml'
ORDERX_FILENAME = 'order-x.xml'
ALL_FILENAMES = [FACTURX_FILENAME, ORDERX_FILENAME]

PROFILES = [
    ('facturx_minimum', 'Minimum'),
    ('facturx_basicwl', 'Basic WL'),
    ('facturx_basic', 'Basic'),
    ('facturx_en16931', 'EN 16931 (Comfort)'),
    ('facturx_extended', 'Extended'),
    ('orderx_basic', 'Basic (Order-X)'),
    ('orderx_comfort', 'Comfort (Order-X)'),
    ('orderx_extended', 'Extended (Order-X)'),
    ]

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
    }

ORDERX_xmp2level = {
    'BASIC': 'orderx_basic',
    'COMFORT': 'orderx_comfort',
    'EXTENDED': 'orderx_extended',
    }

PROFILES_schematron_analysis = ('facturx_en16931', 'facturx_basic', 'orderx_extended', 'orderx_comfort', 'orderx_basic')


class FacturxAnalysis(models.Model):
    _name = 'facturx.analysis'
    _description = 'Factur-X Analysis and Validation'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'id desc'

    name = fields.Char(string='Number', readonly=True, copy=False)  # sequence
    partner_id = fields.Many2one(
        'res.partner', string='Partner', ondelete='restrict', tracking=True)
    title = fields.Char(string='Title', tracking=True)
    date = fields.Datetime(string='Analysis Date', readonly=True, copy=False)
    facturx_file = fields.Binary(
        string='File', copy=False, states={'done': [('readonly', True)]})
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
    xml_schematron_valid = fields.Boolean(  # only for profile en16931 and basic
        'XML valid against Schematron', readonly=True, copy=False)
    valid = fields.Boolean('Fully Valid', readonly=True, copy=False)
    xmp_profile = fields.Selection(
        PROFILES, string='XMP Profile', readonly=True, copy=False)
    xml_profile = fields.Selection(
        PROFILES, string='XML Profile', readonly=True, copy=False)
    error_ids = fields.One2many(
        'facturx.analysis.error', 'parent_id', string='Errors',
        readonly=True)
    xmp_file = fields.Binary(string='XMP File', readonly=True, copy=False)
    xmp_filename = fields.Char(readonly=True, copy=False)
    xml_file = fields.Binary(string='XML File', readonly=True, copy=False)
    xml_filename = fields.Char(readonly=True, copy=False)
    doc_type = fields.Selection([
        ('facturx', 'Factur-X'),
        ('orderx', 'Order-X'),
        ], readonly=True, tracking=True)
    xml_orderx_type = fields.Selection(
        ORDERX_TYPES, string='XML Order-X Type', readonly=True, copy=False)
    xmp_orderx_type = fields.Selection(
        ORDERX_TYPES, string='XMP Order-X Type', readonly=True, copy=False)
    afrelationship = fields.Char(string='AFRelationship', readonly=True, copy=False)

    @api.model
    def create(self, vals):
        if vals.get('name', '/') == '/':
            vals['name'] = self.env['ir.sequence'].next_by_code(
                'facturx.analysis')
        return super(FacturxAnalysis, self).create(vals)

    def back_to_draft(self):
        self.ensure_one()
        self.write({
            'state': 'draft',
            'pdfa3_valid': False,
            'xmp_valid': False,
            'xml_valid': False,
            'xml_schematron_valid': False,
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
            '4_xml_schematron': [],
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
                pdf = PdfFileReader(f)
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
            if rest:
                pdfa_errors = self.analyse_verapdf_rest(vals, vera_xml_root)
            else:
                pdfa_errors = self.analyse_verapdf_subprocess(vals, vera_xml_root)
            if pdfa_errors:
                self.vera_errors_reformat(pdfa_errors, errors)
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
        if xml_root:
            self.analyse_xml_xsd(vals, xml_root, errors)
        else:
            vals['doc_type'] = 'facturx'
        # Starting from here, we have vals['doc_type'] and vals['xml_profile']
        if vals['file_type'] == 'pdf':
            if (vals.get('afrelationship') and vals['afrelationship'] != '/Data' and vals['xml_profile'] in ('facturx_minimum', 'facturx_basicwl')):
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
        if vals.get('xml_profile') in ('facturx_en16931', 'facturx_basic') and xml_bytes:
            self.analyse_xml_schematron_facturx(vals, xml_bytes, errors, prefix)
        elif vals.get('xml_profile') in ('orderx_extended', 'orderx_comfort', 'orderx_basic') and xml_root is not None:
            self.analyse_xml_schematron_orderx(vals, xml_root, errors, prefix)
        if not errors['3_xml']:
            vals['xml_valid'] = True
        if vals.get('xml_profile') in PROFILES_schematron_analysis and not errors['4_xml_schematron']:
            vals['xml_schematron_valid'] = True
        if vals['file_type'] == 'pdf':
            if not errors['1_pdfa3']:
                vals['pdfa3_valid'] = True
            if (
                    vals.get('pdfa3_valid') and
                    vals.get('xmp_valid') and
                    vals.get('xml_valid') and
                    vals.get('xmp_profile') and
                    vals.get('xmp_profile') == vals.get('xml_profile') and
                    vals.get('xmp_orderx_type') == vals.get('xml_orderx_type')
                    ):
                vals['valid'] = True
        elif vals['file_type'] == 'xml':
            if vals.get('xml_valid'):
                vals['valid'] = True
        if vals.get('xml_profile') in PROFILES_schematron_analysis and not vals.get('xml_schematron_valid'):
            vals['valid'] = False
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
            xmp_bytes = metaobj.getData()
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
                    'comment': "For tag '%s' (or attribute '%s' of tag '%s'), the value is '%s' whereas the value should be '%s'" % (xpath_str, tag_name, desc_xpath_str, res.get(tag_name), ' or '.join(tags[tag_name])),
                    })
            elif vals['doc_type'] == 'orderx' and tag_name == 'DocumentType':
                vals['xmp_orderx_type'] = res[tag_name].lower()
            elif tag_name == 'ConformanceLevel':
                vals['xmp_profile'] = xmp2level[res[tag_name]]
        return

    def _get_dict_entry(self, node, entry):
        if not isinstance(node, dict):
            raise ValueError('The node must be a dict')
        dict_entry = node.get(entry)
        if isinstance(dict_entry, dict):
            return dict_entry
        elif isinstance(dict_entry, IndirectObject):
            res_dict_entry = dict_entry.getObject()
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
            kids_node = kid_entry.getObject()
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
        for (filename, file_obj) in embeddedfiles_by_two:
            if filename in ALL_FILENAMES:
                try:
                    xml_file_dict = file_obj.getObject()
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
                    xml_string = xml_file_dict['/EF']['/F'].getData()
                    xml_file_subdict = xml_file_dict['/EF']['/F'].getObject()
                except Exception:
                    errors['1_pdfa3'].append({
                        'name': 'Unable to extract the file %s' % filename,
                        'comment': 'Wrong value for /EF/F for file %s' % filename,
                        })
                    continue
                # The absence of /Subtype is reported by veraPDF
                if (
                        xml_file_subdict.get('/Subtype') and
                        xml_file_subdict['/Subtype'] not in ['/text#2Fxml', '/text#2fxml']):
                    errors['1_pdfa3'].append({
                        'name': 'Wrong value for /EF/F/Subtype',
                        'comment': "Value for /EF/F/Subtype should be '/text#2Fxml'. "
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
            errors['3_xml'].append({
                'name': 'No embedded factur-x.xml file',
                })
        return xml_root, xml_string

    def analyse_xml_xsd(self, vals, xml_root, errors):
        # Order-X or Factur-X ?
        flavor = get_flavor(xml_root)
        if flavor == 'factur-x':
            vals['doc_type'] = 'facturx'
        elif flavor == 'order-x':
            vals['doc_type'] = 'orderx'
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
                'comment': 'The XML file is neither an Order-X nor a Factur-X file.',
            })
            return
        # Check profile
        namespaces = xml_root.nsmap  # NO because it may not contain good nsmap
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
        # check XSD
        try:
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
        # As the SCH of Order-X are ISO SCH and not XSTL2, we can use lxml
        paths = {
            'facturx.orderx.schematron.basic.sch_path': False,
            'facturx.orderx.schematron.comfort.sch_path': False,
            'facturx.orderx.schematron.extended.sch_path': False,
            }
        self._config_parameter_filepath_update(paths)
        if not vals['xml_profile'].startswith('orderx_'):
            raise UserError(_("Wrong XML profile %s. Must be an Order-X profile. This should never happen.") % vals['xml_profile'])
        sch_key = 'facturx.orderx.schematron.%s.sch_path' % vals['xml_profile'][7:]
        sch_path = paths[sch_key]
        try:
            sch_root = etree.parse(sch_path)
        except Exception as e:
            raise UserError(_(
                "Cannot parse SCH XML file %s. Error: %s") % (sch_path, e))
        schematron = Schematron(sch_root, store_report=True)
        res = schematron.validate(xml_root)
        logger.debug('analyse_xml_schematron_orderx res=%s', res)
        svrl_xml_string = schematron.validation_report
        logger.debug('orderx svrl_xml_string=%s', svrl_xml_string)
        svrl_root = etree.fromstring(str(svrl_xml_string))
        if res is False:
            logger.info('Order-X file is invalid according to Schematron')
            self.schematron_result_analysis(vals, svrl_root, errors)
        else:
            logger.info('Order-X file is valid according to Schematron')

    def analyse_xml_schematron_facturx(self, vals, xml_bytes, errors, prefix=None):
        # As the SCH of FacturX uses XSLT2, we can't use lxml
        # cf https://stackoverflow.com/questions/46767903/schematronparseerror-invalid-schematron-schema-for-isosts-schema
        # and https://lxml.de/validation.html#id2
        xml_file = NamedTemporaryFile('wb+', prefix=prefix, suffix='.xml')
        xml_file.write(xml_bytes)
        xml_file.seek(0)
        result_xml_file = NamedTemporaryFile('wb+', prefix=prefix, suffix='.xml')
        paths = {
            'facturx.schematron.jar_path': False,
            'facturx.schematron.xslt_path': False,
            }
        self._config_parameter_filepath_update(paths)
        cmd_list = [
            '/usr/bin/java',
            '-jar',
            paths['facturx.schematron.jar_path'],
            '-xml',
            xml_file.name,
            '-xslt',
            paths['facturx.schematron.xslt_path'],
            '-svrl',
            result_xml_file.name,
            ]
        logger.info('Start to spawn java schematron for %s', self.name)
        logger.debug('java schematron cmd: %s', cmd_list)
        try:
            process = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False)
            out, err = process.communicate()
            if err:
                logger.error('Schematron analysis output errors: %s', err)
            logger.info(
                'Java schematron analysis finished successfully for %s. '
                'Output: %s', self.name, out)
        except Exception as e:
            logger.error('Failed to spawn java schematron. Error: %s', e)
            errors['4_xml_schematron'].append({
                'name': 'Technical failure in Schematron test',
                'comment': '%s' % e,
            })
            return
        result_xml_file.seek(0)
        try:
            svrl_root = etree.parse(result_xml_file.name)
        except Exception as e:
            logger.error(
                'Failed to parse XML result file of schematron '
                'analysis. Error: %s', e)
            errors['4_xml_schematron'].append({
                'name': 'Failed to parse result of Schematron test',
                'comment': '%s' % e,
            })
            return
        self.schematron_result_analysis(vals, svrl_root, errors)
        xml_file.close()
        result_xml_file.close()

    def schematron_result_analysis(self, vals, svrl_root, errors):
        namespaces = {}
        sch_errors = svrl_root.xpath(
            "/*[local-name() = 'schematron-output']/*[local-name() = 'failed-assert']",
            namespaces=namespaces)
        for sch_error in sch_errors:
            detail_xpath = sch_error.xpath("*[local-name() = 'text']", namespaces=namespaces)
            if detail_xpath:
                comment = detail_xpath[0].text and detail_xpath[0].text.strip()
                location = sch_error.attrib and sch_error.attrib.get('location')
                if location:
                    comment += '\nLocation of the error: %s' % location
                if comment:
                    # analysis via java for Factur-X will have an 'id' attrib
                    # but analysis via lxml for Order-X won't, so we use the 'test' attrib
                    errors['4_xml_schematron'].append({
                        'name': sch_error.attrib.get('id') or sch_error.attrib.get('test'),
                        'comment': comment,
                        })

    def run_verapdf_rest(self, vals, f):
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
        logger.debug('veraPDF command: %s', cmd_list)
        process = subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False)
        out, err = process.communicate()
        if err:
            logger.error('Error output in subprocess call: %s', err)
        logger.debug('subprocess out=%s', out)
        logger.info('End veraPDF for %s', self.name)
        vera_xml_root = ET.fromstring(out)
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
            res[group2label[err.error_group]].append({'name': err.name, 'comment': err.comment})
        return res


class FacturxAnalysisError(models.Model):
    _name = 'facturx.analysis.error'
    _description = 'Factur-X Analysis Errors'
    _order = 'parent_id, error_group, id'

    parent_id = fields.Many2one('facturx.analysis', ondelete='cascade')
    # It's not a good idea to name that field 'group' because
    # it's a special word in SQL
    error_group = fields.Selection([
        ('1_pdfa3', 'PDF/A-3'),
        ('2_xmp', 'XMP'),
        ('3_xml', 'XML XSD'),
        ('4_xml_schematron', 'XML Schematron'),
        ], string='Group', required=True)
    name = fields.Char(required=True)
    comment = fields.Text()
