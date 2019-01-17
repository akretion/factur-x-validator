# -*- coding: utf-8 -*-
# Copyright 2018 Akretion France (https://www.akretion.com/)
# @author: Alexis de Lattre <alexis.delattre@akretion.com>

from odoo import api, fields, models, _
from odoo.exceptions import UserError
import lxml.etree as ET
import requests
import subprocess
from tempfile import NamedTemporaryFile
import re
import os
import hashlib
import mimetypes
from lxml import etree
from collections import OrderedDict
from PyPDF2 import PdfFileReader
from facturx import check_facturx_xsd
import logging
logger = logging.getLogger(__name__)

FACTURX_FILENAME = 'factur-x.xml'

PROFILES = [
    ('minimum', 'Minimum'),
    ('basicwl', 'Basic WL'),
    ('basic', 'Basic'),
    ('en16931', 'EN 16931 (Comfort)'),
    ]

FACTURX_xmp2LEVEL = {
    'MINIMUM': 'minimum',
    'BASIC WL': 'basicwl',
    'BASIC': 'basic',
    'EN 16931': 'en16931',
    }

FACTURX_LEVEL2XSD = {
    'minimum': 'FACTUR-X_BASIC-WL.xsd',
    'basicwl': 'FACTUR-X_BASIC-WL.xsd',
    'basic': 'FACTUR-X_EN16931.xsd',
    'en16931': 'FACTUR-X_EN16931.xsd',
    }


class FacturxAnalysis(models.Model):
    _name = 'facturx.analysis'
    _description = 'Factur-X Analysis and Validation'
    _inherit = ['mail.thread']
    _order = 'id desc'

    name = fields.Char(string='Number', readonly=True, copy=False)  # sequence
    partner_id = fields.Many2one(
        'res.partner', string='Customer', ondelete='restrict',
        track_visibility='onchange', domain=[('customer', '=', True)])
    title = fields.Char(string='Title', track_visibility='onchange')
    date = fields.Datetime(string='Analysis Date', readonly=True, copy=False)
    facturx_file = fields.Binary(
        string='Factur-X File', copy=False,
        states={'done': [('readonly', True)]})
    facturx_filename = fields.Char(
        string='Factur-X Filename', copy=False, track_visibility='onchange')
    facturx_file_sha1 = fields.Char(
        string='SHA1 Sum', readonly=True, copy=False,
        track_visibility='onchange')
    facturx_file_size = fields.Integer(
        string='File Size', readonly=True, copy=False,
        track_visibility='onchange')
    file_type = fields.Selection([
        ('pdf', 'PDF'),
        ('xml', 'XML'),
        ], string='File Type', readonly=True, copy=False)
    state = fields.Selection(
        [('draft', 'Draft'), ('done', 'Done')],
        string='State', readonly=True, default='draft', copy=False,
        track_visibility='onchange')
    pdfa3_valid = fields.Boolean(string='Valid PDF/A-3', readonly=True, copy=False)
    xmp_valid = fields.Boolean('Valid XMP', readonly=True, copy=False)
    xml_valid = fields.Boolean(
        'Factur-X XML valid against XSD', readonly=True, copy=False)
    xml_schematron_valid = fields.Boolean(  # only for profile en16931
        'Factur-X XML valid against Schematron', readonly=True, copy=False)
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
        })

    @api.model
    def errors2errors_write(self, errors):
        errors_write = []
        for group, err_list in errors.items():
            for err in err_list:
                assert isinstance(err, dict)
                errors_write.append((0, 0, dict(err, group=group)))
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
                vals = {'file_type': 'xml'}
            elif filetype[0] != 'application/pdf':
                raise UserError(_(
                    "The Factur-X file has not been recognised as a PDF file "
                    "(MIME Type: %s). Please check the filename extension.")
                    % filetype[0])
        prefix = self.facturx_filename and self.facturx_filename[:4] + '-'\
            or 'facturx-'
        suffix = '.%s' % vals['file_type']
        f = NamedTemporaryFile('wb+', prefix=prefix, suffix=suffix)
        f.write(self.facturx_file.decode('base64'))
        f.seek(0)
        if vals['file_type'] == 'pdf':
            try:
                pdf = PdfFileReader(f)
                pdf_root = pdf.trailer['/Root']
            except:
                raise UserError(_("This is not a PDF file"))
            rest = False
            try:
                logger.info('Connecting to veraPDF via Rest')
                vera_xml_root = self.run_verapdf_rest(vals, f)
                rest = True
            except:
                logger.warning(
                    'Failed to connect to veraPDF via Rest. '
                    'Fallback to subprocess method')
                vera_xml_root = self.run_verapdf_subprocess(vals, f)
            if rest:
                pdfa_errors = self.analyse_verapdf_rest(vals, vera_xml_root)
            else:
                pdfa_errors = self.analyse_verapdf_subprocess(vals, vera_xml_root)
            if pdfa_errors:
                self.vera_errors_reformat(pdfa_errors, errors)
            xmp_root = self.extract_xmp(vals, pdf_root, errors)
            if xmp_root:
                self.analyse_xmp(vals, xmp_root, errors)

            xml_root, xml_string = self.extract_xml(vals, pdf_root, errors)

            if not errors['1_pdfa3']:
                vals['pdfa3_valid'] = True
            if not errors['2_xmp']:
                vals['xmp_valid'] = True

        elif vals['file_type'] == 'xml':
            xml_string = self.facturx_file.decode('base64')
            xml_root = False
            try:
                xml_root = etree.fromstring(xml_string)
            except Exception as e:
                errors['3_xml'].append({
                    'name': u'Not a valid XML file',
                    'comment': u'Technical error message:\n%s' % e,
                    })
        if xml_root:
            self.analyse_xml_xsd(vals, xml_root, errors)
        if vals.get('xml_profile') == 'en16931' and xml_string:
            self.analyse_xml_schematron(vals, xml_string, errors, prefix)
        if not errors['3_xml']:
            vals['xml_valid'] = True
        if vals.get('xml_profile') == 'en16931' and not errors['4_xml_schematron']:
            vals['xml_schematron_valid'] = True
        if vals['file_type'] == 'pdf':
            if (
                    vals.get('pdfa3_valid') and
                    vals.get('xmp_valid') and
                    vals.get('xml_valid') and
                    vals.get('xmp_profile') and
                    vals.get('xmp_profile') == vals.get('xml_profile')):
                vals['valid'] = True
        elif vals['file_type'] == 'xml':
            if vals.get('xml_valid'):
                vals['valid'] = True
        if vals.get('xml_profile') == 'en16931' and not vals.get('xml_schematron_valid'):
            vals['valid'] = False
        facturx_file_size = os.stat(f.name).st_size
        f.seek(0)
        facturx_file_sha1 = hashlib.sha1(f.read()).hexdigest()
        f.close()
        logger.debug('vals at end of analysis=%s', vals)
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
            xmp_string = metaobj.getData()
        except Exception as e:
            errors['2_xmp'].append({
                'name': u'No valid /Metadata in PDF structure',
                'comment': u"Cannot extract content of /Metadata from PDF",
                })
            return False
        # print "xmp=", xmp_string
        vals.update({
            'xmp_file': xmp_string.encode('base64'),
            'xmp_filename': 'metadata_%s.xml' % self.name.replace('/', '_'),
            })
        xmp_root = False
        try:
            xmp_root = etree.fromstring(xmp_string)
        except Exception as e:
            errors['2_xmp'].append({
                'name': u'XMP Metadata file is not a valid XML file',
                'comment': u'Technical error message:\n%s' % e,
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
                'name': u'Required tag missing in XMP Metadata',
                'comment': u'Missing path /x:xmpmeta/rdf:RDF/rdf:Description '
                           u'in XMP Metadata',
                })
            return
        tags = {
            'DocumentType': ['INVOICE'],
            'DocumentFileName': [FACTURX_FILENAME],
            'Version': ['1.0'],
            'ConformanceLevel': FACTURX_xmp2LEVEL.keys(),
            }
        res = {}
        for desc_node in desc_xpath:
            for tag_name in tags.keys():
                xpath_str = desc_xpath_str + '/fx:' + tag_name
                tag_xpath = xmp_root.xpath(
                    xpath_str, namespaces=namespaces)
                if tag_xpath:
                    res[tag_name] = tag_xpath[0].text and tag_xpath[0].text.strip() or False
        for tag_name, tag_val in tags.items():
            xpath_str = desc_xpath_str + '/fx:' + tag_name
            if tag_name not in res:
                errors['2_xmp'].append({
                    'name': u"Required tag '%s' missing" % tag_name,
                    'comment': u"Missing tag %s in XMP Metadata" % xpath_str,
                    })
            elif res.get(tag_name) not in tags[tag_name]:
                errors['2_xmp'].append({
                    'name': u"Wrong value for tag '%s'" % tag_name,
                    'comment': u"For tag '%s', the value is '%s' whereas the value should be '%s'" % (xpath_str, res.get(tag_name), ' or '.join(tags[tag_name])),
                    })
            elif tag_name == 'ConformanceLevel':
                vals['xmp_profile'] = FACTURX_xmp2LEVEL[res[tag_name]]
        return

    def extract_xml(self, vals, pdf_root, errors):
        xml_root = xml_string = False
        try:
            embeddedfiles = pdf_root['/Names']['/EmbeddedFiles']['/Names']
        except:
            errors['1_pdfa3'].append({
                'name': u'Missing /Names/EmbeddedFiles/Names in PDF structure',
                })
            return False
        # embeddedfiles must contain an even number of elements
        if len(embeddedfiles) % 2 != 0:
            errors['1_pdfa3'].append({
                'name': u'Wrong value for /Names/EmbeddedFiles/Names in PDF structure',
                'comment': u'/Names/EmbeddedFiles/Names should contain '
                           u'an even number of elements',
                })
            return False
        embeddedfiles_by_two = zip(embeddedfiles, embeddedfiles[1:])[::2]
        logger.debug('embeddedfiles_by_two=%s', embeddedfiles_by_two)
        facturx_file_present = False
        for (filename, file_obj) in embeddedfiles_by_two:
            if filename == FACTURX_FILENAME:
                try:
                    xml_file_dict = file_obj.getObject()
                except:
                    errors['1_pdfa3'].append({
                        'name': u'Unable to get the PDF file object %s' % filename,
                        })
                    continue
                # If '/AFRelationship' not in xml_file_dict reported by veraPDF
                if '/Type' not in xml_file_dict:
                    errors['1_pdfa3'].append({
                        'name': u'Missing entry /Type in File Specification Dictionary',
                        })
                elif xml_file_dict.get('/Type') != '/Filespec':
                    errors['1_pdfa3'].append({
                        'name': u'Wrong value for /Type in File Specification Dictionary',
                        'comment': u"Value for /Type in File Specification "
                                   u"Dictionary should be '/Filespec'. "
                                   u"Current value is '%s'." % xml_file_dict.get('/Type')
                        })
                # presence of /F and /UF already checked by VeraPDF
                for entry in ['/F', '/UF']:
                    if xml_file_dict.get(entry) != FACTURX_FILENAME:
                        errors['1_pdfa3'].append({
                            'name': u'Wrong value for %s in File Specification Dictionary' % entry,
                            'comment': u"Value for %s in File Specification "
                                       u"Dictionary should be 'factur-x.xml'. "
                                       u"Current value is '%s'." % (entry, xml_file_dict.get(entry))
                            })

                afrel_accepted = ['/Data', '/Source', '/Alternative']
                if '/AFRelationship' not in xml_file_dict:
                    errors['1_pdfa3'].append({
                        'name': 'Missing /AFRelationship entry for file %s' % filename,
                        })
                elif xml_file_dict.get('/AFRelationship') not in afrel_accepted:
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
                except:
                    errors['1_pdfa3'].append({
                        'name': u'Unable to extract the file %s' % filename,
                        'comment': u'Wrong value for /EF/F for file %s' % filename,
                        })
                    continue
                # The absence of /Subtype is reported by veraPDF
                if xml_file_subdict.get('/Subtype') != '/text#2Fxml':
                    errors['1_pdfa3'].append({
                        'name': u'Wrong value for /EF/F/Subtype',
                        'comment': u"Value for /EF/F/Subtype should be '/text#2Fxml'. "
                                   u"Current value is '%s'." % xml_file_subdict.get('/Subtype')
                        })
                if '/Type' not in xml_file_subdict:
                    errors['1_pdfa3'].append({
                        'name': u'Missing entry /EF/F/Type',
                        })
                elif xml_file_subdict.get('/Type') != '/EmbeddedFile':
                    errors['1_pdfa3'].append({
                        'name': u'Wrong value for /EF/F/Type',
                        'comment': u"Value for /EF/F/Type should be '/EmbeddedFile'. "
                                   u"Current value is '%s'." % xml_file_subdict.get('/Type')
                        })
                facturx_file_present = True
                try:
                    xml_root = etree.fromstring(xml_string)
                except Exception as e:
                    errors['3_xml'].append({
                        'name': u'factur-x.xml file is not a valid XML file',
                        'comment': u'Technical error message:\n%s' % e,
                        })
                    continue
                vals['xml_file'] = xml_string.encode('base64')
                vals['xml_filename'] = 'factur-x_%s.xml' % self.name.replace('/', '_')

        if not facturx_file_present:
            errors['3_xml'].append({
                'name': u'No embedded factur-x.xml file',
                })
        return xml_root, xml_string

    def analyse_xml_xsd(self, vals, xml_root, errors):
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
                "cannot read the Factur-X profile and therefore we cannot test "
                "against the XSD.",
                })
            return
        doc_id = doc_id_xpath[0].text
        if not doc_id:
            errors['3_xml'].append({
                'name': 'Empty tag in XML file',
                'comment': "The tag ExchangedDocumentContext/"
                "GuidelineSpecifiedDocumentContextParameter/ID "
                "is empty, so we cannot read the Factur-X profile and "
                "therefore we cannot test against the XSD.",
                })
            return
        doc_id_split = doc_id.split(':')
        xml_profile = doc_id_split[-1]
        if xml_profile not in FACTURX_LEVEL2XSD and len(doc_id_split) > 1:
            xml_profile = doc_id.split(':')[-2]
        if xml_profile not in FACTURX_LEVEL2XSD:
            errors['3_xml'].append({
                'name': "Invalid Factur-X URN",
                'comment': "Invalid Factur-X URN '%s' in the XML tag "
                           "ExchangedDocumentContext/"
                           "GuidelineSpecifiedDocumentContextParameter/ID" % doc_id,
                })
            return
        vals['xml_profile'] = xml_profile
        # check XSD
        try:
            check_facturx_xsd(
                xml_root, flavor='factur-x', facturx_level=xml_profile)
        except Exception as e:
            errors['3_xml'].append({
                'name': u'factur-x.xml file invalid against XSD',
                'comment': u'%s' % e,
            })
        return

    def analyse_xml_schematron(self, vals, xml_string, errors, prefix=None):
        facturx_xml_file = NamedTemporaryFile('w+', prefix=prefix, suffix='.xml')
        facturx_xml_file.write(xml_string)
        facturx_xml_file.seek(0)
        result_xml_file = NamedTemporaryFile('w+', prefix=prefix, suffix='.xml')
        ico = self.env['ir.config_parameter'].sudo()
        paths = {
            'facturx.schematron.jar_path': False,
            'facturx.schematron.xslt_path': False,
            }
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
        cmd_list = [
            '/usr/bin/java',
            '-jar',
            paths['facturx.schematron.jar_path'],
            '-xml',
            facturx_xml_file.name,
            '-xslt',
            paths['facturx.schematron.xslt_path'],
            '-svrl',
            result_xml_file.name,
            ]
        logger.info('Start to spawn java schematron for %s', self.name)
        try:
            process = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False)
            out, err = process.communicate()
            logger.info(
                'Java schematron analysis finished successfully for %s. '
                'Output: %s', self.name, out)
        except Exception as e:
            logger.error('Failed to spawn java schematron. Error: %s', e)
            return
        result_xml_file.seek(0)
        xml_result_string = result_xml_file.read()
        logger.debug('xml_result_string=%s', xml_result_string)
        try:
            xml_result_root = etree.fromstring(xml_result_string)
        except Exception as e:
            logger.error(
                'Failed to parse XML result file of schematron '
                'analysis. Error: %s', e)
            return
        namespaces = xml_result_root.nsmap
        namespaces.pop(None)
        sch_errors = xml_result_root.xpath(
            "/*[local-name() = 'schematron-output']/*[local-name() = 'failed-assert']",
            namespaces=namespaces)
        for sch_error in sch_errors:
            detail_xpath = sch_error.xpath("*[local-name() = 'text']", namespaces=namespaces)
            if detail_xpath:
                comment = detail_xpath[0].text
                location = sch_error.attrib and sch_error.attrib.get('location')
                if location:
                    comment += '\nError location: %s' % location
                if comment:
                    errors['4_xml_schematron'].append({
                        'name': sch_error.attrib.get('id'),
                        'comment': comment,
                        })
        facturx_xml_file.close()
        result_xml_file.close()

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
        vera_xml_root = ET.fromstring(xml_string)
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
            '--add-modules',  # required for openjdk 10 (not for openjdk 8)
            'java.xml.bind',
            '-classpath',
            classpath,
            #  '-Dfile.encoding=UTF8',  # MARCHE
            #  '-XX:+IgnoreUnrecognizedVMOptions',
            #  '--add-modules=java.xml.bind',
            #  '-Dapp.name="VeraPDF validation CLI"',
            #  '-Dapp.repo="/opt/verapdf/bin"',
            #  '-Dapp.home="/opt/verapdf"',
            #  '-Dbasedir="/opt/verapdf"',
            'org.verapdf.apps.GreenfieldCliWrapper',
            f.name,
            ]
        logger.info('Start to spawn veraPDF for %s', self.name)
        process = subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False)
        out, err = process.communicate()
        logger.info('End veraPDF for %s', self.name)
        vera_xml_root = ET.fromstring(out)
        return vera_xml_root

    def analyse_verapdf_rest(self, vals, vera_xml_root):
        errors = []
        namespaces = vera_xml_root.nsmap
        profile_xpath = vera_xml_root.xpath(
            '/ValidationResultImpl/pdfaflavour', namespaces=namespaces)
        profile = profile_xpath and profile_xpath[0].text or False
        compliant_xpath = vera_xml_root.xpath(
            '/ValidationResultImpl/compliant', namespaces=namespaces)
        compliant = compliant_xpath and compliant_xpath[0].text or False
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
            "/ValidationResultImpl/testAssertions/testAssertions",
            namespaces=namespaces)
        tmp_errors = {}
        for verrors in errors_xpath:
            spec_xpath = verrors.xpath(
                'ruleId/specification', namespaces=namespaces)
            spec = spec_xpath and spec_xpath[0].text or False
            clause_xpath = verrors.xpath(
                'ruleId/clause', namespaces=namespaces)
            clause = clause_xpath and clause_xpath[0].text or False
            test_number_xpath = verrors.xpath(
                'ruleId/testNumber', namespaces=namespaces)
            test_number = test_number_xpath\
                and test_number_xpath[0].text or False
            status_xpath = verrors.xpath(
                'status', namespaces=namespaces)
            status = status_xpath and status_xpath[0].text or False
            if status != 'FAILED':
                raise UserError(_(
                    "Wrong Rest XML output: STATUS = %s (should be FAILED)")
                    % status)
            msg_xpath = verrors.xpath(
                'message', namespaces=namespaces)
            msg = msg_xpath and msg_xpath[0].text or False
            if msg:
                msg = msg.replace('\n\t\t', ' ')  # Cleanup
            level_xpath = verrors.xpath(
                'location/level', namespaces=namespaces)
            level = level_xpath and level_xpath[0].text or False
            vcontext_xpath = verrors.xpath(
                'location/context', namespaces=namespaces)
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
            msg_raw = verrors.xpath('description', namespaces=namespaces)[0].text
            msg = re.sub('\s+', ' ', msg_raw)
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
        action = self.env['report'].get_action(self, 'facturx.analysis.report')
        return action

    def report_get_errors(self):
        self.ensure_one()
        faeo = self.env['facturx.analysis.error']
        group2label = dict(faeo.fields_get('group', 'selection')['group']['selection'])
        res = OrderedDict()
        for err in self.error_ids:
            if err.group in res:
                res[err.group].append({'name': err.name, 'comment': err.comment})
            else:
                res[err.group] = [{'name': err.name, 'comment': err.comment}]
        fres = OrderedDict()
        for key, value in res.iteritems():
            fres[group2label[key]] = value
        # from pprint import pprint
        # pprint(fres)
        return fres


class FacturxAnalysisError(models.Model):
    _name = 'facturx.analysis.error'
    _description = 'Factur-X Analysis Errors'
    _order = 'parent_id, group, id'

    parent_id = fields.Many2one('facturx.analysis', ondelete='cascade')
    group = fields.Selection([
        ('1_pdfa3', 'PDF/A-3'),
        ('2_xmp', 'XMP'),
        ('3_xml', 'XML XSD'),
        ('4_xml_schematron', 'XML Schematron'),
        ], string='Group', required=True)
    name = fields.Char(required=True)
    comment = fields.Text()
