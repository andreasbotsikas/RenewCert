RenewCert
=========

[Renew click once certificates](http://msdn.microsoft.com/en-us/library/ff369721.aspx) by adding 105 years to their expiration date.

This code was originally provided by Microsoft and then modified by [Cliff Stanford](http://may.be/renewcert/).

Updated to add more years to the certificate (and avoid renewing every 5 years).

Usage
=====
    renewcert <PFX File> <new cert filename> <new cert friendly name> (<password>)

**Examples**

With password protection:

    renewcert oldcert.pfx newcert.pfx "CN=MyNewCert" MySuperSecretPassword

Without password protection: 

    renewcert oldcert.pfx newcert.pfx "CN=MyNewCert"

Build
=====

Build using visual studio 2013. An [express version](http://www.visualstudio.com/downloads/download-visual-studio-vs#d-express-windows-8) will do.
