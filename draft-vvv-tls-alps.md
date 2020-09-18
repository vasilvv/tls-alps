---
title: "TLS Application-Layer Protocol Settings Extension"
abbrev: "TLS ALPS"
docname: draft-vvv-tls-alps
category: std

ipr: trust200902
area: General
workgroup: TLS Working Group
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: V. Vasiliev
    name: Victor Vasiliev
    organization: Google
    email: vasilvv@google.com

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
ALPS mechanism similar to QUIC transport parameters
{{?I-D.ietf-quic-transport}} or HTTP/2 SETTINGS frame {{?RFC7540}}, but puts it
in contrast to similar mechanisms in TLS.

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

# Wire protocol

ALPS is only supported in TLS version 1.3 or later, as the earlier versions do
not provide any confidentiality protections for the handshake data.  The
exchange is performed in three steps:

1. The client sends an extension in ClientHello that enumerates all ALPN values
   for which ALPS is supported.
1. The server sends an encrypted extension containing the server settings.
1. The client sends a new handshake message containing the client settings.

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

       {ClientApplicationSettings}
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

A TLS client can enable ALPS by specifying an `application_settings` extension.
The value of the `extension_data` field for the ALPS extension SHALL be a
ApplicationSettingsSupport struct:

        struct {
            ProtocolName supported_protocols<2..2^16-1>;
        } ApplicationSettingsSupport;

Here, the `supported_protocols` field indicates the names of the protocols (as
defined in {{!RFC7301}}) for which ALPS exchange is supported; this is necessary
for the situations when the client offers multiple ALPN values but only supports
ALPS in some of them.

If the server chooses an ALPN value for which the client has offered ALPS
support, the server MAY send an `application_settings` extension in the
EncryptedExtensions.  The value of the `extension_data` field in that case SHALL
be an opaque blob containing the server settings as specified by the application
protocol.

If the client receives an EncryptedExtensions message containing an
`application_settings` extension from the server, after receiving server's
Finished message it MUST send a ClientApplicationSettings handshake message
before sending the Finished message:

        enum {
            client_application_settings(TBD), (255)
        } HandshakeType;

        struct {
            opaque application_settings<0..2^16-1>;
        } ClientApplicationSettings;

The value of the `application_settings` field SHALL be an opaque blob containing
the client settings as specified by the application protocol.  If the client is
providing a client certificate, the ClientApplicationSettings message MUST
precede the Certificate message sent by the client.

If the ClientApplicationSettings message is sent or received during the
handshake, it SHALL be appended to the end of client's Handshake Context
context as defined in Section 4.4 of {{!RFC8446}}.  In addition, for
Post-Handshake Handshake Context, it SHALL be appended after the client
Finished message.

## 0-RTT Handshakes

ALPS ensures settings are available before reading and writing application data,
so handshakes which negotiate early data instead use application settings from
the PSK. To use early data with a PSK, the TLS implementation MUST associate both
client and server application settings, if any, with the PSK. For a resumption
PSK, these values are determined from the original connection. For an external
PSK, this values should be configured with it. Existing PSKs are considered to
not have application settings.

If the server accepts early data, the server SHALL NOT send an
`application_settings` extension, and thus the client SHALL NOT send a
ClientApplicationSettings message. Instead, the connection implicitly uses the
PSK's application settings, if any. If the server rejects early data,
application settings are negotiated independently of the PSK, as if early data
were not offered.

If the client wishes to send different client settings for the connection,
it MUST NOT offer 0-RTT.  Conversely, if the server wishes to use send different
server settings, it MUST reject 0-RTT.  Note that the ALPN itself is similarly
required to match the one in the original connection, thus the settings
only need to be remembered or checked for a single application protocol.
Implementations are RECOMMENDED to first determine the desired application
protocol and settings independent of early data, and then decline to offer or
accept early data if the values do not match the PSK. This preserves any ALPN
and ALPS configuration specified by the calling application.

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
this extension may appear is `CH, EE`.

IANA will also update the "TLS HandshakeType" registry to include
`client_application_settings` message with value TBD, and "DTLS-OK" set to "Y".


--- back

# Acknowledgments
{:numbered="false"}

This document has benefited from contributions and suggestions from David
Benjamin, Nick Harper, David Schinazi, Renjie Tang and many others.
