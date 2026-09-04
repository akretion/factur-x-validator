# Copyright 2026 Akretion France (https://www.akretion.com/)
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).
"""Backfill facturx.analysis.error.severity for rows created before the
severity/rule_id fields were introduced.

Odoo already fills the new NOT NULL column with the field default ('error')
when it adds it during -u, so this is only belt-and-suspenders for any row
that could have been left NULL.
"""


def migrate(cr, version):
    if not version:
        return
    cr.execute(
        "UPDATE facturx_analysis_error SET severity = 'error' "
        "WHERE severity IS NULL"
    )
