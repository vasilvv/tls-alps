---
title: "TLS Application-Layer Protocol Settings Extension"
abbrev: "TLS ALPS"
docname: draft-vvv-tls-alps-latest
category: std

ipr: trust200902
area: General
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: D. Benjamin
    name: David Benjamin
    organization: Google
    email: davidben@google.com
 -
    ins: V. Vasiliev
    name: Victor Vasiliev
    organization: Google
    email: vasilvv@google.com
 -
    ins: V. Tan
    name: Victor Tan
    organization: Google LLC
    email: victortan@google.com

normative:
  RFC2119:

informative:


--- abstract

This document describes a Transport Layer Security (TLS) extension for
negotiating application-layer protocol settings (ALPS) within the TLS handshake.
Any application-layer protocol operating over TLS can use this mechanism to
indicate its settings to the peer in parallel with the TLS handshake
completion.

--- middle

# Introduction

An application-layer protocol often starts with both parties negotiating
parameters under which the protocol operates; for instance, HTTP/2 {{?RFC7540}}
uses a SETTINGS frame to exchange the list of protocol parameters supported by
each endpoint.  This is usually achieved by waiting for TLS handshake
{{!RFC8446}} to complete and then performing the application-layer handshake
within the application protocol itself.  This approach, despite its apparent
simplicity at first, has multiple drawbacks:

1. While the server is technically capable of sending configuration to the peer
   as soon as it sends its Finished message, most TLS implementations do not
   allow any application data to be sent until the Finished message is received
   from the client.  This adds an extra round-trip to the time of when the
   server settings are available to the client.
1. In QUIC, any settings delivered within the application layer can arrive
   after other application data; thus, the application has to operate under the
   assumption that peer's settings are not always available.
1. If the application needs to be aware of the server settings in order to send
   0-RTT data, the application has to manually integrate with the TLS stack to
   associate the settings with TLS session tickets.

This document introduces a new TLS extension, `application_settings`, that
allows applications to exchange settings within the TLS handshake.  Through
doing that, the settings can be made available to the application as soon as the
handshake completes, and can be associated with TLS session tickets
automatically at the TLS layer.  This approach allows the application protocol
to be designed with the assumption that it has access to the peer's settings
whenever it is able to send data.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Semantics

Settings are defined to be an opaque blob that is specified by the application
when initiating a TLS connection.  The settings are meant to be a *declaration*
of the protocol parameters supported by the sender.  While in this version of
the extension the server settings are always sent first, this may change in
future versions; thus, the application MUST NOT vary client settings based on
the ones received from the server.

ALPS is *not* a negotiation mechanism: there is no notion of rejecting peer's
settings, and the settings are not responses to one another.  Nevertheless, it
is possible for parties to coordinate behavior by, for instance, requiring a
certain parameter to be present in both client and server settings.  This makes
ALPS mechanism similar to QUIC transport parameters {{?RFC9000}} or HTTP/2
SETTINGS frame {{?RFC7540}}, but puts it in contrast to similar mechanisms in
TLS.

Settings are exchanged as a part of the TLS handshake that is encrypted with the
handshake keys.  When the server settings are sent, the identity of the client
has not been yet established; therefore, an application MUST NOT use ALPS if it
requires the settings to be available only to the authenticated clients.

The ALPS model provides applications with a guarantee that the settings are
available before any application data can be written.  Note that this implies
that when the full handshake is performed, the server can no longer send data
immediately after sending its Finished message; it has to wait for the client
to respond with its settings.  This may negatively impact the latency of the
protocols where the server sends the first message, however it should be noted
that sending application data before receiving has not been widely supported by
TLS implementations, nor has it been allowed in situations when establishing
client identity through TLS is required.

ALPS can only be used in conjunction with Application-Layer Protocol
Negotiation: the client MUST offer ALPN {{!RFC7301}} if advertising ALPS
support, and the server MUST NOT reply with ALPS unless it is also negotiating
ALPN.  The ALPS payload is protocol-dependent, and as such it MUST be specified
with respect to a selected ALPN.

# Wire Protocol

ALPS is only supported in TLS version 1.3 or later, as the earlier versions do
not provide any confidentiality protections for the handshake data.  The
exchange is performed in three steps:

1. The client sends an extension in ClientHello that enumerates all ALPN values
   for which ALPS is supported.
1. The server sends an encrypted extension containing the server settings.
1. The client sends an encrypted extension containing the client settings.

~~~
       Client                                               Server

       ClientHello
       + alpn
       + alps                    -------->

                                                       ServerHello
                                             {EncryptedExtensions}
                                                            + alpn
                                                            + alps
                                                               ...
                                 <--------              {Finished}

       {EncryptedExtensions}
       + alps
       {Certificate*}
       {CertificateVerify*}
       {Finished}                -------->

                   +  Indicates extensions sent in the
                      previously noted message.

                   {} Indicates messages protected using
                      the handshake keys.

                   *  Indicates optional messages that are
                      not related to ALPS.
~~~
{: #alps-full title="ALPS exchange in a full TLS handshake"}

A TLS client can enable ALPS by specifying an `application_settings` extension
in the ClientHello message. An early experimental deployment of this protocol
used the value 17513 for `application_settings`. It was then replaced with an
experimental deployment which used the value 17613. The value of the
`extension_data` field for this extension SHALL be a ApplicationSettingsSupport
struct:

        struct {
            ProtocolName supported_protocols<2..2^16-1>;
        } ApplicationSettingsSupport;

Here, the `supported_protocols` field indicates the names of the protocols (as
defined in {{!RFC7301}}) for which ALPS exchange is supported; this is necessary
for the situations when the client offers multiple ALPN values but only supports
ALPS in some of them.

If the server chooses an ALPN value for which the client has offered ALPS
support, the server MAY additionally negotiate ALPS in this connection and
determine a server settings value. This is an opaque blob as specified by the
ALPN protocol. If not accepting early data (see {{early-data}}), the server then
sends an `application_settings` extension in its EncryptedExtensions message.
The value of the `extension_data` field in that case SHALL the server settings
value.

If the client receives an EncryptedExtensions message containing an
`application_settings` extension from the server, it first checks that ALPN was
negotiated and that the selected ALPN protocol was one of the ones advertised in
ApplicationSettingsSupport. If not, it MUST abort the connection with an
"illegal_parameter" alert. Otherwise, it MUST send an EncryptedExtensions
message (see {{encrypted-extensions}}) containing an `application_settings`
extension. The value of the `extension_data` in this extension SHALL be an
opaque blob containing the client settings as specified by the application
protocol. A server which negotiates ALPS MUST abort the handshake with a
`missing_extension` alert if the client's EncryptedExtensions is missing this
extension.

## Client Encrypted Extensions {#encrypted-extensions}

This specification introduces the client EncryptedExtensions message. The
format and HandshakeType code point match the server EncryptedExtensions
message. When sent, it is encrypted with handshake traffic keys and sent by the
client after receiving the server Finished message and before the client sends
the Certificate, CertificateVerify (if any), and Finished messages. It SHALL be
appended to the Client Handshake Context, as defined in {{Section 4.4 of
!RFC8446}}. It additionally SHALL be inserted after the server Finished in the
Post-Handshake Handshake Context.

The client MUST send the EncryptedExtensions message if any extension sent in
the server EncryptedExtension message contains the CEE token in the TLS 1.3
column of the TLS ExtensionType Values registry. Otherwise, the client MUST NOT
send the message. The server MUST abort the handshake with a
`unexpected_message` alert if the message was sent or omitted incorrectly.

The client MAY send an extension in the client EncryptedExtension message if
that extension's entry in the registry contains a CEE token and the server
EncryptedExtensions message included the extension. Otherwise, the client MUST
NOT send the extension. If a server receives an extension which does not meet
this criteria, it MUST abort the handshake with an `unsupported_extension`
alert.

Future extensions MAY use the client EncryptedExtensions message by including
the CEE token in the TLS 1.3 registry. The above rules ensure clients will not
send EncryptedExtensions messages to older servers, but will send
EncryptedExtensions when some negotiated extension uses it.

\[\[TODO: Section 4.6.1 of RFC8446 allows the server to predict the client
Finished flight and send a ticket early. This is still possible with 0-RTT
handshakes here because we omit rather than repeat the redudant ALPS
information, but, in the general extension case, client EncryptedExtensions
breaks this. Extension order is unpredictable. We should resolve this conflict,
either by dropping that feature or removing flexibility here.\]\]

## 0-RTT Handshakes {#early-data}

ALPS ensures settings are available before reading and writing application data,
so handshakes which negotiate early data instead use application settings from
the PSK. To use early data with a PSK, the TLS implementation MUST associate
both client and server application settings, if any, with the PSK. For a
resumption PSK, these values are determined from the original connection. For an
external PSK, this values should be configured with it. Existing PSKs are
considered to not have application settings.

When sending a ClientHello, clients MUST NOT offer early data with a PSK that
has application settings if the PSK's client application settings are different
from those the client would send for the PSK's ALPN protocol. If the PSK does
not have application settings, the client MAY offer early data with the PSK
independent of its ALPS configuration.

When processing a ClientHello, in addition to the checks specified by {{Section
4.2.10 of RFC8446}}, the server MUST verify the following before accepting
early data:

- If the server did not negotiate ALPS for the connection, the PSK does not
  have application settings.

- If the server did negotiate ALPS for the connection, the PSK has application
  settings and the PSK's server settings value matches the value selected by the
  server.

If either check fails, the server MUST NOT accept early data. It MAY continue to
negotiate the PSK.

If the server accepts early data, the server SHALL NOT send an
`application_settings` extension, and thus the client SHALL NOT send a
`application_settings` extension in its EncryptedExtensions message. Unless the
server has sent some other extension which uses client EncryptedExtensions, the
client SHALL NOT send an EncryptedExtensions message. Instead, the connection
implicitly uses the PSK's application settings, if any.

If the server rejects early data, application settings are negotiated
independently of the PSK, as if early data were not offered.

The checks in this section are analogous to the requirement that ALPN is
preserved across early data. They ensure that early data does not change the
result of the ALPN or ALPS negotiation.

# Using ALPS in an Application Protocol

Protocols using ALPS MUST define an application profile describing how the
negotiated settings values are used in the protocol. Absent such a profile,
client and server applications MUST NOT configure their TLS implementations to
negotiate ALPS with the corresponding ALPN value. The profile MUST define the
syntaxes of the client and server protocol settings values and how they are
processed.

Protocols MAY mandate the use of ALPS when negotiated over TLS. This may be
appropriate for new protocols that can depend on ALPS. Applications
implementing the protocol would then check that ALPS was negotiated and, if
not, terminate the connection.

Alternatively, protocols MAY make the use of ALPS optional. This may be
appropriate for existing protocols, where there is already a deployment of
non-ALPS clients or servers. ALPS would then be an extension to the existing
protocol, and the application profile would define the protocol changes when
negotiated. Note that, for any given connection, ALPS will be consistently
negotiated or not negotiated on both the client and server. This means
adjusting protocol behavior based on ALPS is unambiguous.

As described in {{early-data}}, early data does not change the result of the
ALPS negotiation, so protocols that use TLS early data MAY change client and
server ALPS preferences across connections. However, when either value changes,
early data is rejected. Thus protocols using both ALPS and early data SHOULD
ensure the client and server preferences change infrequently. For example, the
set of HTTP/2 extensions {{?RFC7540}} implemented by a server only changes when
new features are deployed. However, including different reserved setting
identifiers (see {{Section 7.2.4.1 of ?I-D.ietf-quic-http}}) in each connection
would not perform well.

# Security Considerations

ALPS is protected using the handshake keys, which are the secret keys derived
as a result of (EC)DHE between the client and the server.

In order to ensure that the ALPS values are authenticated, the TLS
implementation MUST NOT reveal the contents of peer's ALPS until peer's
Finished message is received, with exception of cases where the ALPS has been
carried over from the previous connection.

# IANA Considerations

IANA will update the "TLS ExtensionType Values" registry to include
`application_settings` with the value of TBD; the list of messages in which
this extension may appear is `CH, EE, CEE`.


--- back

# Acknowledgments
{:numbered="false"}

This document has benefited from contributions and suggestions from Nick
Harper, David Schinazi, Renjie Tang and many others.
