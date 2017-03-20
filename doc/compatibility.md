Due to the difference between how the Krb5 and NTLM challenge-response
mechanisms work, not all software using GSSAPI successfully works yet.

[SIPE](http://sipe.sourceforge.net/) 1.18.x and later are GSS-NTLMSSP
compatible and in the process of making it work many bugs have been
fixed on all sides.
Many thanks to Stefan Becker and David Woodhouse for the collaboration
and making this possible.

[Firefox](https://mozilla.org/firefox) (multiple versions) has been
tested and seem to work without issues.

[Curl](http://curl.haxx.se/) instead seem to assume that the GSSAPI
conversation will always be completed in one roundtrip so it fails to
work with GSS-NTLMSSP as the NTLM challenge-response protocol requires
two or more roundtrips unlike the Krb5 mechanism.
UPDATE: Fixed in curl git as of 2014-07-16 just after the 7.37.1 release.

[Cyrus-SASL](http://cyrusimap.org/)'s GSS-SPNEGO support is equally
broken with GSS-NTLMSSP, the actual authentication works fine, but then
it fails to correctly negotiate the SASL SSF properties due again to the
incorrect assumption that the authentication negotiation always
terminates with the last message being sent from the server to the client.
In NTLMSSP usually the last message is from the client back to the server.
UPDATE: The GSS-SPNEGO mechanism in Cyrus-SASL has been recently fixed to
work correctly with the reference implementation (MS Windows), at least
with the Krb5 mechanism, additional testing for GSS-NTLMSSP is needed now.
