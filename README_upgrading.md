## UPGRADING
# AUTHOR: sebastien.maurines@akretion.com
# PURPOSE: explain how the upgrade has been operated

## FIRST-UPGRADE
# WHAT: adding EXTENDED-CTC-FR
# WHEN: first deployment 18MAY2026
# HOW: modifying facturx/facturx.py and facturx_validator/models/facturx_analysis.py
# WHO: sebastien.maurines@akretion.com

I have needed to create the environment o14-ctc-fr doing a copy-paste of "erp/o14"
because of this library call: "from facturx import xml_check_xsd, get_flavor, get_orderx_type" into facturx_validator/models/facturx_analysis.py
