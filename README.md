# BankID Open B2B Examples

This repository contains code examples for BankID Open B2B.

The documentation for BankID Open B2B is located [here](doc/BankID-Open-B2B.md)


## Disclaimer
The code in this repository is provided as _examples_ for using BankID Open B2B. The code is not accurate or complete enough for banks, merchants, partners or vendors to rely on without further amendment. BankID Norge is not responsible for any errors or omissions.

## Organization of example code
                                LOCATION                CONTENT DESCRIPTION

    Usage examples:             src/main/java           Java code
     (i.e. how to sign and
      validate with an
      Open B2B BankID)

    Usage scenarios:            src/test/java           Java code
     (in the form of            src/test/resources      PKCS#12 keystores for example merchants and VA trust.
      integration tests)                                Logback configuration.

     Tool to convert BID file   makep12/makep12.zip     Small java application to be used to convert bidfiles to PKCS#12

Also see documentation for [Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html).

**TIP!** A good starting point for getting familiar with the code is the integration tests, which implements the usage scenarios.
