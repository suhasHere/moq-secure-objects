---
title: End-to-End Secure Objects for Media over QUIC Transport
abbrev: MOQT Secure Objects
docname: draft-jennings-moq-secure-objects-latest
category: std

ipr: trust200902
stream: IETF
area: "Applications and Real-Time"
keyword: Internet-Draft
v: 3
venue:
  group: "Media over QUIC"
  type: "Working Group"
  mail: "moq@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/moq/"
  github: "suhasHere/moq-secure-objects"
  latest: "https://suhashere.github.io/moq-secure-objects/#go.draft-jennings-moq-secure-objects.html"

author:
 -
    name: Cullen Jennings
    organization: Cisco
    email: fluffy@cisco.com
 -
    name: Suhas Nandakumar
    organization: Cisco
    email: snandaku@cisco.com
 -
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx


normative:

informative:

--- abstract

This document describes an end-to-end authenticated encryption scheme for
application objects intended to be delivered over Media over QUIC Transport
(MOQT).  We reuse the SFrame scheme for authenticated encryption of media
objects, while suppressing data that would be redundant between SFrame and MOQT,
for an efficient on-the-wire representation.

--- middle

# Introduction

Media Over QUIC Transport (MOQT) is a protocol that is optimized for the QUIC
protocol, either directly or via WebTransport, for the dissemination of delivery
of low latency media {{!I-D.ietf-moq-transport}}. MOQT defines a
publish/subscribe media delivery layer across set of participating relays for
supporting wide range of use-cases with different resiliency and latency (live,
interactive) needs without compromising the scalability and cost effectiveness
associated with content delivery networks. It supports sending media objects
through sets of relays nodes.

Typically a MOQ Relay doesn't need to access the media content, thus allowing
the media to be "end-to-end" encrypted so that it cannot be decrypted by the
relays. However for a relay to participate effectively in the media delivery, it
needs to  access naming information of a MOQT object to carryout the required
store and forward functions.

As such, two layers of security are required:

1. Hop-by-hop (HBH) security between two MOQT relays

2. End-to-end (E2E) security from the Publisher of an MOQT object to End
   Subscribers

The HBH security is provided by TLS in the QUIC connection that MOQT
runs over. MOQT support different E2EE protection as well as allowing
for E2EE security.

This document defines a scheme for E2E authenticated encryption of MOQT objects.
This scheme is based on the SFrame mechanism for authenticated encryption of
media objects {{!I-D.ietf-sframe-enc}}.

However, a secondary goal of this design is to minimize the amount of additional
data the encryptions requires for each object. This is particularly important
for very low bit rate audio applications where the encryption overhead can
increase overall bandwidth usage by a significant percentage.  To minimize the
overhead added by end-to-end encryption, certain fields that would be redundant
between MOQT and SFrame are not transmitted.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals, as shown here.

This document re

E2EE:
: End to End Encryption

HBH:
: Hop By Hop

Producer:
: Software that creates and encrypts MoQ Objects.

Consumer:
: Software that decrypts MoQ Objects.

# MOQT Object Model Recap {#moqt}

MOQT defines a publish/subscribe based media delivery protocol, where in
endpoints, called producers, publish objects which are delivered via
participating relays to receiving endpoints, called consumers.

{{Section 2 of I-D.ietf-moq-transport}} defines hierarchical object model for
application data, comprised of objects, groups and tracks.

Objects defines the basic data element, an addressable unit whose
payload is sequence of bytes. All objects belong to a group, indicating
ordering and potential dependencies. A track contains a sequence of
groups and serves as the entity against which a consumer issues a
subscription request.

~~~ aasvg
Media Over QUIC Application
|
|                                                           time
+-- TrackA --+---------+-----+---------+-------+---------+------>
|            | Group1  |     | Group2  |  ...  | GroupN  |
|            +----+----+     +----+----+       +---------+
|                 |               |
|                 |               |
|            +----+----+     +----+----+
|            | Object0 |     | Object0 |
|            +---------+     +---------+
|            | Object1 |     | Object1 |
|            +---------+     +---------+
|            | Object2 |     | Object2 |
|            +---------+     +---------+
|                ...
|            +---------+
|            | ObjectN |
|            +---------+
|
|                                                          time
+-- TrackB --+---------+-----+---------+-------+---------+------>
             | Group1  |     | Group2  |  ...  | GroupN  |
             +----+----+     +----+----+       +----+----+
                  |               |                 |
                  |               |                 |
             +----+----+     +----+----+       +----+----+
             | Object0 |     | Object0 |       | Object0 |
             +---------+     +---------+       +---------+
~~~
{: #fig-moqt-session title="Structure of an MOQT session" }

Objects are comprised of two parts: envelope and a payload. The envelope
is never end to end encrypted and is always visible to relays. The
payload portion may be end to end encrypted, in which case it is only
visible to the producer and consumer. The application is solely
responsible for the content of the object payload.

Tracks are identified by a combination of its TrackNamespace and
TrackName.  TrackNamespace and TrackName are treated as a sequence of
binary bytes.  Group and Objects are represented as variable length
integers called GroupId and ObjectId respectively.

For purposes of this specification, we define `FullTrackName` as :

~~~
FullTrackName = TrackNamespace | TrackName
~~~

where `|` representations concatenation of byte strings,

and  `ObjectName` is combination of following properties:

~~~
ObjectName = (FullTrackName, GroupId, ObjectId)
~~~

Two important properties of objects are:

1. ObjectNames are globally unique in a given relay network.

2. The data inside an object ( and it's size) can never change after the
object is first published. There can never be two objects with the same
name but different data.

One of the ways system keep the object names unique is by using a fully
qualified domain names or UUIDs as part of the TrackNamespace.

# Secure Objects

A Secure MOQT Object is MOQT OBJECT_STREAM or OBJECT_DATAGRAM messages that has
been protected with the scheme defined in this draft, so that its payload is
encrypted and the whole message is authenticated by an authentication tag in the
payload:

~~~ aasvg
OBJECT_STREAM Message {
  Subscribe ID (i),
  Track Alias (i),
  Group ID (i),             <-- authenticated
  Object ID (i),            <-- authenticated
  Object Send Order (i),
  Object Status (i),
  Object Payload (..),      <-- encrypted and authenticated
}
~~~
{: #fig-encrypted-object title="Security properties of a secure OBJECT_STREAM
object.  Protection of an OBJECT_DATAGRAM message is analogous." }

~~~ aasvg
+-------------+-----------------------------------------+
| KID (i) ... |                                         |
+-------------+                                         |
|                                                       |
|                                                       |
|                                                       |
|                                                       |
|                   Encrypted Data                      |
|                                                       |
|                                                       |
|                                                       |
|                                                       |
+-------------------------------------------------------+
|                 Authentication Tag                    |
+-------------------------------------------------------+
~~~
{: #fig-secure-object-payload title="The payload of a secure object" }

Specifically, the payload of a secure object comprises a varint-encoded KID
value, followed by  the "encrypted data" and
"authentication tag" portions of an SFrame ciphertext object, as described in
{{Section 4.2 of !I-D.ietf-sframe-enc}}.  That is, the secure object payload is
an SFrame ciphertext without the SFrame Header.  Rather than transmitting the
SFrame Header, MOQT producers and consumers synthesize it from the information
in the object being protected, as described in {{mapping-between-sframe-and-moqt}}.

## Setup Assumptions

This scheme applies SFrame on a per-track basis.  We assume that the application
assigns each track a set of (KID, `base_key`) tuples, where each `base_key` is
known only to authorized producer and consumers for a given track. How these
per-track secrets are established is outside the scope of this specification. We
also assume that the application defines which KID should be used for a given
encryption operation.  (For decryption, the KID is obtained from the object
payload.)

It is also up to the application to specify the ciphersuite to be used for each
track's SFrame context.  Any SFrame ciphersuite can be used.

> **NOTE:** This is described as having a single key per track right now, for
> simplicity.  It will likely be useful to have multiple keys per track, e.g.,
> to accommodate a track spanning multiple MLS epochs.  You could also
> accommodate multiple senders in the same track this way, though that seems
> problematic for other reasons (namely object name uniqueness).  In any case,
> these variants can be distinguished by KID, and the KID will have to be
> carried in the protected object payload.

> **NOTE:** You could also use the track names to derive keys off of a master
> key, something like `track_base_key = HKDF(track_id, master_key)`.  This could
> be useful, e.g., if the `master_key` is exported from MLS.  SFrame will also
> derive different base keys for different KID values, so in principle, you
> could use the KID to distinguish tracks.  But as discussed above, we probably
> want to use the KID for other purposes.

## Mapping Between SFrame and MOQT

MOQT secure objects are protected and unprotected by means of the analogous
SFrame operations.  SFrame the protect operation requires KID, CTR, and metadata
inputs, and produces an SFrame ciphertext structure as output; the unprotect
operation takes as input an SFrame ciphertext (including KID and CTR in a
header) and metadata.

~~~ aasvg
+-+----+-+----+--------------------+--------------------+
|K|KLEN|C|CLEN|    Key ID = App    | Counter = Grp+Obj  | <---- Synthesized
+-+----+-+----+--------------------+--------------------+ -.
|                                                       |   |
|                                                       |   |
|                                                       |   |
|                                                       |   |
|                   Encrypted Data                      |   |
|                                                       |   +-- MOQT Object
|                                                       |   |   Payload
|                                                       |   |
|                                                       |   |
+-------------------------------------------------------+   |
|                 Authentication Tag                    |   |
+-------------------------------------------------------+ -'
~~~
{: #fig-sframe-ciphertext title="An SFrame, as it relates to MOQT" }

For protect/unprotect of MOQT objects, the KID, CTR and metadata fields are
constructed as follows:

* The KID value is provided by the application, as discussed in
  {{setup-assumptions}}.

* The CTR value comprises the encoding of Group ID and Object ID as QUIC
  varints, padded to 8 bytes on the right, interpreted as a 64-bit big-endian
  integer. (Note that this implies that the total bit length of the encoded
  Group ID and Object ID MUST be less than 64).

``` python
def encode_varint(x):
    if x < 0x40:
        return (x, 8)
    elif x < 0x4000:
        return (0x4000 + x, 16)
    elif x < 0x40000000:
        return (0x80000000 + x, 32)
    elif x < 0x4000000000000000:
        return (0xc000000000000000 + x, 64)

def encode_ctr(group_id, object_id):
    (group_id, group_bits) = encode_varint(group_id)
    (object_id, object_bits) = encode_varint(object_id)

    group_shift = 64 - group_bits
    object_shift = group_shift - object_bits

    return (group_id << group_shift) | (object_id << object_shift)
```

* The `metadata` field is the FullTrackName value for the track within which the
  object is being sent.

## Protect

To construct an MOQT secure object from an unprotected MOQT object, we perform
an SFrame encryption and then throw away the SFrame header (since it can be
reconstructed by the other side).

1. Select the appropriate SFrame context for the track (see
   {{setup-assumptions}}).

2. Compute the CTR, and metadata values for the object (see
   {{mapping-between-sframe-and-moqt}}).

3. Perform an SFrame encryption with the KID value provided by the application,
   the computed CTR and metadata values, and the plaintext parameter set to the
   payload of the MOQT object (as described in {{Section 4.4.3 of
   I-D.ietf-sframe-enc}}), returning an SFrame ciphertext object.

4. Construct an MOQT secure object of the same type as the input object, with
   the following context:
    * Set the payload to the contents of the "encrypted data" and
      "authentication tag" portion of the SFrame ciphertext.
    * Set the other fields of the message to the corresponding fields from the
      input message.

Note that the offset of the required bytes in the SFrame ciphertext can be
computed by parsing the "config byte" which is the first byte of the SFrame
ciphertext.

~~~ pseudocode
def moqt_protect(full_track_name, kid, object):
    # Idenitfy the appropriate SFrame context
    ctx = sframe_context_for_track(full_track_name)

    # Compute the required SFrame parameters
    ctr = encode_ctr(object.group_id, object.object_id)
    metadata = full_track_name

    # Perform an SFrame encryption
    sframe_ciphertext = ctx.encrypt(kid, ctr, metadata, object.payload)

    # Replace the object's payload with the encrypted data
    (encoded_kid, _) = encode_varint(kid)
    ciphertext_offset = sframe_header_len(sframe_ciphertext[0])
    object.payload = encoded_kid + sframe_ciphertext[ciphertext_offset:]
~~~

## Decryption

To transform an MOQT secure object back into its plaintext form, we first
synthesize an SFrame ciphertext representing the encrypted payload, and then
decrypt it to obtain the payload for the MOQT object.

1. Select the appropriate SFrame context for the track (see
   {{setup-assumptions}}).

2. Compute the CTR and metadata values for the object (see
   {{mapping-between-sframe-and-moqt}}).

3. Parse the payload of the MOQT secure object to obtain:
    a. The KID value
    b. The SFrame ciphertext data

4. Construct an SFrame ciphertext:
    * Construct an SFrame header value that represents KID and CTR
      values, as defined in {{Section 4.3 of I-D.ietf-sframe-enc}}.
    * Append to the SFrame header the SFrame ciphertext data parsed from the
      object payload.

5. Perform an SFrame decryption with the SFrame ciphertext and the computed
   metadata as input, as described in {{Section 4.4.4 of I-D.ietf-sframe-enc}},
   returning a plaintext value.

6. Construct an MOQT object of the same type as the input object, with
   the following context:
    * Set the payload to the plaintext value returned by SFrame decryption.
    * Set the other fields of the message to the corresponding fields from the
      input message.

~~~ pseudocode
def moqt_unprotect(full_track_name, object):
    # Idenitfy the appropriate SFrame context
    ctx = sframe_context_for_track(full_track_name)

    # Parse the object payload
    (kid, kid_byte_len) = parse_varint(object.payload)
    sframe_ciphertext_data = object.payload[kid_byte_len:]

    # Compute the required SFrame parameters
    ctr = encode_ctr(object.group_id, object.object_id)
    metadata = full_track_name

    # Synthesize an SFrame ciphertext
    header = encode_sframe_header(kid, ctr)
    sframe_ciphertext = concat(header, sframe_ciphertext_data)

    # Perform an SFrame decryption
    plaintext = ctx.decrypt(metadata, sframe_ciphertext)

    # Replace the object's payload with the decrypted data
    object.payload = plaintext
~~~

# Security Considerations {#security}

The SFrame specification lists several things that an application needs to
account for in order to use SFrame securely, which are all accounted for here:

1. **Header value uniqueness:** Uniqueness of SFrame CTR values follows from the
   uniqueness of MOQT (group ID, object ID) pairs.  We only use one KID value,
   but instead use distinct SFrame contexts with distinct keys per track.  This
   assures that the same (`base_key`, KID, CTR) tuple is never used twice.

2. **Key management:** We delegate this to the MOQT application, with subject to
   the assumptions described in {{setup-assumptions}}.

3. **Anti-replay:** Replay is not possible within the MOQT framework because of
   the uniqueness constraints on object IDs and objects, and because the group
   ID and object ID are cryptographically bound to the secure object payload.

4. **Metadata:** The content of the metadata input to SFrame operations is
   defined in {{mapping-between-sframe-and-moqt}}.

> **NOTE:** It is not clear to me that the anti-replay point actually holds up
> here, but that is probably just due to the limitations of my understanding of
> MOQT.  How is a receiver or relay supposed to be have if its next upstream hop
> sends it multiple values with the same track name, group ID, and object ID?

Any of the SFrame ciphersuites defined in the relevant IANA registry can be used
to protect MOQT objects.  The caution against short tags in {{Section 7.5 of
I-D.ietf-sframe-enc}} still applies here, but the MOQT environment provides some
safeguards that make it safer to use short tags, namely:

* MOQT has hop-by-hop protections provided by the underlying QUIC layer, so a
  brute-force attack could only be mounted by a relay.

* MOQT tracks have predictable object arrival rates, so a receiver can interpret
  a large deviation from this rate as a sign of an attack.

* The the binding of the secure object payload to other MOQT parameters (as
  metadata), together with MOQT's uniqueness properties ensure that a valid
  secure object payload cannot be replayed in a different context.

# IANA Considerations {#iana}

This document makes no request of IANA.

--- back

# Acknowledgements

TODO
