# Copyright 2018-2021 Akretion France (https://www.akretion.com/)
# @author: Alexis de Lattre <alexis.delattre@akretion.com>

from odoo import fields, models, _


class ResPartner(models.Model):
    _inherit = 'res.partner'

    analysis_count = fields.Integer(compute='_compute_analysis_count')

    def _compute_analysis_count(self):
        rg_res = self.env['facturx.analysis'].read_group(
            [('partner_id', 'in', self.ids)],
            ['partner_id'], ['partner_id'])
        mapped_data = dict(
            [(x['partner_id'][0], x['partner_id_count']) for x in rg_res])
        for partner in self:
            partner.analysis_count = mapped_data.get(partner.id, 0)

