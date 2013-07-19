
GSS-NTLMSSP
===========

This is a mechglue plugin for the GSSAPI library that implements NTLM
authentication.

So far it has been built and tested only with the libgssapi implementation
that comes with MIT Kerberos 1.11


BUILDING
========

See BUILD.txt


TESTING
=======

Testsuite:
----------

Run ./ntlmssptest at your leisure, it just insures that the crypto is
working correctly.

Real testing:
-------------

There are exactly 2 configuration knobs at this point, and both need to
be set right.

1. The gss configruation file.

In orde to load the mechanism into gssapy copy the content of the file
examples/mech.ntlmssp into /etc/gss/mech
If you are installing in a non standard path check that the location
of the shared object matches where you installed it in your system

2. The credentials file

Set the environment variable NTLM_USER_FILE to a path to a file with
your NTLM cedentials in it.
The file format is the same as the one used by the gss ntlm mechanism
that can be found in Heimdal. Super simple, one or more lines with:
DOMAIN:USERNAME:PASSWORD as elements separated by ':'

For example:
ADDOM:Administrator:Passw0rd

Testing Application:
--------------------

So far the only application that seem to properly use GSSAPI and
therfore will work unmodified is Firefox. I tried also Curl, but even
after making some patches to let it use the builtin SPNEGO implementation
of GSSAPI it seem that the code is hardcoded to believe there will always
only ever be one roundtrip. This is not necessarily true with the krb5
mechanism although it works with that with current implementations.
I will need more patches for curl, meanwhile use firefox.

The server: I am using a Windows Server with IIS installed and Windows
Authentication enabled.

In Firefox go in about:config and set the string list named
network.negotiate-auth.trusted-uris to your Windows server domain
name suffix. This is necessary otherwise Firefox will not even attempt to
perform negotiation, regardles of the Mechanism used.

Example:
network.negotiate-auth.trusted-uris = .addom.example.com

