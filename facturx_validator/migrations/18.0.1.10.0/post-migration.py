# Copyright 2026 Akretion France (https://www.akretion.com/)
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).
"""Tier-2 backfill for Factur-X analyses carried over from 14.0.

14.0 kept every schematron finding in a single group ``4_xml_schematron`` with
only ``{name, comment}``:

  * ``name``    held the SVRL ``@test`` attribute -- the "when" xpath -- or the
                literal ``"Schematron error"`` when the SVRL row had no @test
                (the Order-X lxml path, mostly);
  * ``comment`` held the SVRL text, which repeats the rule id as a
                ``"[BR-CO-09]-..."`` prefix, followed by
                ``"\\nLocation of the error: ..."``.

18.0 split that pass into a profile pass (``4_xml_schematron_profile``) and a
systematic BR-FR pass (``5_xml_schematron_br_fr``), and added ``rule_id`` /
``test_condition`` / ``severity`` on the error line plus per-pass ruleset names
on ``facturx.analysis``.  A migrated 14.0 row therefore lands in a group the
current report label map no longer knows -> ``report_get_errors`` raised
``KeyError: '4_xml_schematron'`` and the whole PDF failed.

This migration reconstructs the 18.0 shape from the data 14.0 already stored
(no re-analysis, so it is cheap and changes no verdict):

  * ``rule_id``        <- parsed from the ``[ID]-`` / ``ID/BT-nn : `` prefix of
                          ``comment`` (falls back to ``name``); ``NULL`` when
                          nothing parses (Order-X rows -- same as a fresh run).
  * ``error_group``    <- ``5_xml_schematron_br_fr`` when that id starts with
                          ``BR-FR``, else ``4_xml_schematron_profile``.
  * ``test_condition`` <- the old ``name`` when it looks like an xpath / @test;
                          the "when" line is thus only as complete as 14.0
                          captured it.
  * ``name``           <- ``'failed-assert'`` to match fresh rows (the report
                          heading now comes from ``rule_id``, not ``name``).
  * ``severity``       <- normalised to ``'fatal'`` (14.0 had no warning
                          concept); this also repairs the invalid ``'error'``
                          value written by migrations/18.0.1.0.0.
  * ``facturx.analysis.schematron_profile_ruleset`` /
    ``schematron_br_fr_ruleset`` <- basename of the *current* ruleset for the
                          stored ``xml_profile``.  Reads as "the ruleset that
                          applies to this profile", not necessarily the exact
                          file that judged the invoice in the 14.0 era.

Idempotent: every step is keyed on the legacy ``4_xml_schematron`` value or an
empty target column, so a re-run is a no-op.
"""
import logging
import os

_logger = logging.getLogger(__name__)

# One atomic statement: the CTE reads name/comment *before* the UPDATE
# overwrites name, so partial application can never corrupt the source.
_REMAP_SCHEMATRON_ERRORS = r"""
WITH parsed AS (
    SELECT
        id,
        -- each pattern's FIRST '(' is its only capturing group, so
        -- substring() returns the rule id and nothing else
        COALESCE(
            substring(comment FROM '^\s*\[([A-Za-z0-9][A-Za-z0-9._-]*)\]'),
            substring(comment FROM '^\s*([A-Z][A-Z0-9]+(?:-[A-Za-z0-9]+)+)'),
            substring(name    FROM '^\s*\[([A-Za-z0-9][A-Za-z0-9._-]*)\]')
        ) AS rid,
        CASE
            WHEN name IS NOT NULL
             AND name <> 'Schematron error'
             AND (name LIKE '%(%' OR name LIKE '%/%' OR name LIKE '%@%')
            THEN name
        END AS whn
    FROM facturx_analysis_error
    WHERE error_group = '4_xml_schematron'
)
UPDATE facturx_analysis_error e SET
    rule_id        = parsed.rid,
    test_condition = parsed.whn,
    name           = 'failed-assert',
    severity       = CASE WHEN e.severity IN ('fatal', 'warning')
                          THEN e.severity ELSE 'fatal' END,
    error_group    = CASE WHEN parsed.rid ILIKE 'BR-FR%'
                          THEN '5_xml_schematron_br_fr'
                          ELSE '4_xml_schematron_profile' END
FROM parsed
WHERE e.id = parsed.id
"""

# report_get_errors() and the form view always render the non-schematron
# sections as [fatal]; 18.0.1.0.0 wrote a bogus 'error' into severity.
_FIX_LEGACY_SEVERITY = """
UPDATE facturx_analysis_error SET severity = 'fatal'
WHERE severity IS NULL OR severity NOT IN ('fatal', 'warning')
"""


def _backfill_rulesets(cr):
    try:
        from odoo.addons.facturx_validator.models.facturx_analysis import (
            PROFILE_RULES,
        )
    except Exception:  # pragma: no cover - defensive, never seen
        _logger.warning(
            "facturx 14->18 tier-2: PROFILE_RULES not importable, "
            "skipping schematron ruleset backfill")
        return

    profile_name = {
        k: os.path.basename(v["schematron"])
        for k, v in PROFILE_RULES.items() if v.get("schematron")
    }
    br_fr_name = {
        k: os.path.basename(v["br_fr_schematron"])
        for k, v in PROFILE_RULES.items() if v.get("br_fr_schematron")
    }

    cr.execute("""
        SELECT DISTINCT a.id, a.xml_profile
        FROM facturx_analysis a
        JOIN facturx_analysis_error e ON e.parent_id = a.id
        WHERE e.error_group IN ('4_xml_schematron_profile',
                                '5_xml_schematron_br_fr')
          AND a.xml_profile IS NOT NULL
          AND COALESCE(a.schematron_profile_ruleset, '') = ''
    """)
    rows = cr.fetchall()
    done = 0
    for analysis_id, profile in rows:
        prof = profile_name.get(profile)
        if not prof:
            continue
        cr.execute(
            "UPDATE facturx_analysis SET "
            "schematron_profile_ruleset = %s, "
            "schematron_br_fr_ruleset = "
            "    COALESCE(NULLIF(schematron_br_fr_ruleset, ''), %s) "
            "WHERE id = %s",
            (prof, br_fr_name.get(profile), analysis_id),
        )
        done += 1
    _logger.info("facturx 14->18 tier-2: ruleset name set on %d/%d analyses",
                 done, len(rows))


def migrate(cr, version):
    if not version:
        return

    cr.execute(
        "SELECT count(*) FROM facturx_analysis_error "
        "WHERE error_group = '4_xml_schematron'")
    legacy = cr.fetchone()[0]

    cr.execute(_REMAP_SCHEMATRON_ERRORS)
    remapped = cr.rowcount
    cr.execute(
        "SELECT count(*) FROM facturx_analysis_error "
        "WHERE error_group = '5_xml_schematron_br_fr' AND name = 'failed-assert'")
    to_br_fr = cr.fetchone()[0]
    _logger.info(
        "facturx 14->18 tier-2: remapped %d legacy schematron rows "
        "(was %d; %d now in the BR-FR section)", remapped, legacy, to_br_fr)

    cr.execute(_FIX_LEGACY_SEVERITY)
    _logger.info("facturx 14->18 tier-2: severity normalised on %d rows",
                 cr.rowcount)

    _backfill_rulesets(cr)
