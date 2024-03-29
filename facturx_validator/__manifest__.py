# Copyright 2018-2021 Akretion France (https://www.akretion.com/)
# @author: Alexis de Lattre <alexis.delattre@akretion.com>

{
    'name': 'Factur-X Validator',
    'version': '14.0.1.0.0',
    'category': 'Tools',
    'license': 'AGPL-3',
    'summary': 'Analyse and validate Factur-X invoices',
    'author': 'Akretion',
    'website': 'http://www.akretion.com',
    'depends': [
        'mail',
        'base_company_extension',
        'report_py3o',
        ],
    'external_dependencies': {'python': ['facturx']},
    'data': [
        'data/sequence.xml',
        'data/ir_config_parameter.xml',
        'views/facturx_analysis.xml',
        'views/res_partner.xml',
        'security/ir.model.access.csv',
        'report/report.xml',
        ],
    'installable': True,
}
