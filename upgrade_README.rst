### UPGRADE
# Restucturation of the sch_files in schemas
# Adding the folder testing_files

# Updating PROFILES and SCH_PATH

# New analysis detection
1/ For the next release, detect if it is a e-Invoicing or e-Reporting
=> I have still not evaluate which balise we should use
2/ Determinate if it is a CDAR or e-Invoicing
=> IF "urn.cpro.gouv.fr:1p0:CDV:" in the XML is a CDAR THEN "Your document is a CDAR and next release we will analyse this one too"
3/ Determinate if it is an Order-X or a e-Invoicing document
=> IF CrossIndustryInvoice:100 or SCRDMCCBDACIOMessageStructure:100 = 'order-x' THEN it is not e-Invoicing
4/ Now that we know that our file is an e-Invoicing we must determinate
=> IF it is e-Invocing in a PDF format it is FX
        IF xml contains " <cbc:CustomizationID>urn:cen.eu:" it is an UBL
            ELSE it is a CII or FX analysis

# Import strategy: facturx lib (akretion/factur-x)
# facturx_analysis.py imports: xml_check_xsd, get_flavor, get_orderx_type
# - get_flavor() raises Exception for UBL/CDAR (unknown root tag) => must detect CDAR and UBL BEFORE calling get_flavor()
# - xml_check_xsd() only supports factur-x / order-x => UBL XSD validation to be handled locally (new method analyse_xml_xsd_ubl)
# - CII standalone: same root tag as Factur-X (CrossIndustryInvoice) => get_flavor() returns 'factur-x', no change needed
# => NO fork of facturx.py required