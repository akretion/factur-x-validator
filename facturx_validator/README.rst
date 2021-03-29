.. image:: https://img.shields.io/badge/license-AGPL--3-blue.png
   :target: https://www.gnu.org/licenses/agpl
   :alt: License: AGPL-3

==================
Factur-X Validator
==================

This Odoo module is a tool to validate a Factur-X invoice. Factur-X is the e-invoice standard for France and Germany. The specifications are available in French and English on the `FNFE-MPE website <http://fnfe-mpe.org/factur-x/>`_.

This module is completely independant from the invoicing feature of Odoo. This tool has been developped in Odoo only to benefit from it's web user interface and its reporting engines.

Installation
============

This installation procedure is for Odoo v14.0 on Ubuntu 20.04 LTS.

This tool is a bit complex to install because it uses several Java components.

.. code::

  sudo apt install default-jre maven

Get veraPDF-rest, the tool that analyse the PDF/A conformity:

.. code::

  git clone https://github.com/veraPDF/veraPDF-rest.git
  cd veraPDF-rest
  git checkout integration

If `bug #56 <https://github.com/veraPDF/veraPDF-rest/issues/56>`_ is still open, you should checkout a slightly older version (otherwise, it won't start):


.. code::

  git checkout 7f1970f81d3d55e1804dafbc60596d3f2c5cfb38

Then compile to generate the jar file:

.. code::

  mvn clean package

Starts veraPDF-rest:

.. code::

  java -jar target/verapdf-rest-0.1.0-SNAPSHOT.jar server

You can use *supervisor* to auto-start *veraPDF-rest* on boot:

.. code::

  sudo apt install supervisor

Then create a file */etc/supervisor/conf.d/verapdf.conf* as root that contains (adapt the user and paths to your environnement):

.. code::

  [program:verapdf-rest]
  user=odoo
  command=/usr/bin/java -jar /home/odoo/veraPDF-rest/target/verapdf-rest-0.1.0-SNAPSHOT.jar server
  stdout_logfile=/var/log/odoo/verapdf-rest.log
  redirect_stderr=true
  autostart=true
  autorestart=false

For schematron analysis, you will need the Java tool and the XSLT file compiled from the schematron.

You can get the XSLT file from the Github repo `https://github.com/CenPC434/validation <https://github.com/CenPC434/validation>`_ under the path *cii/xslt/EN16931-CII-validation.xslt*.

To get the Java tool, checkout the Github repo `https://github.com/CenPC434/java-tools <https://github.com/CenPC434/java-tools>`_ and compile it with Maven:

.. code::

  git clone https://github.com/CenPC434/java-tools
  cd java-tools
  mvn clean package

The result JAR file can be found under *en16931-xml-validator/target/en16931-xml-validator-2.0.5-SNAPSHOT-jar-with-dependencies.jar*.

Configuration
=============

Go to the menu *Settings > Technical > Parameters > System parameters* and set the value for all the parameters whose key starts with *facturx.*. It is required to tell Odoo the location of the schematron JAR file, the schematron XSLT file, the URL of veraPDF rest, etc...

If the fallback on veraPDF command line tool doesn't work, edit the Odoo server configuration file:

.. code::

  limit_memory_hard = 8589934592


Usage
=====

Go to the menu *Factur-X > Factur-X Analysis* and click on the *Create* button. Upload the Factur-X PDF file that you want to analyse. Then click on the *Analyse* button.

Bug Tracker
===========

Bugs are tracked on `GitHub Issues
<https://github.com/akretion/factur-x-validator/issues>`_. In case of trouble, please
check there if your issue has already been reported. If you spotted it first,
help us smashing it by providing a detailed and welcomed feedback.

Credits
=======

Contributors
------------

* Alexis de Lattre <alexis.delattre@akretion.com>
