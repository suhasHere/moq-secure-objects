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

## Setup Assumptions

We assume that the application assigns each track a set of (KID, `base_key`)
tuples, where each `base_key` is known only to authorized producer and consumers
for a given track. How these per-track secrets are established is outside the
scope of this specification. We also assume that the application defines
which KID should be used for a given encryption operation.  (For decryption,
the KID is obtained from the object payload.)

It is also up to the application to specify the ciphersuite to be used for each
track's encryption context.  Any SFrame ciphersuite can be used.

## Secure Object Format

The payload of a secure object comprises an AEAD-encrypted object payload, with
a header prepended that specifies the KID in use.

~~~ pseudocode
SECURE_OBJECT {
  Key ID (i),
  Encrypted Data (..),
}
~~~

## Encryption Schema

MOQT secure object protection relies on an SFrame cipher suite to define the
AEAD encryption algorithm and hash algorithm in use {{!RFC9605}}.  We
will refer to the following aspects of the AEAD and the hash algorithm below:

* `AEAD.Encrypt` and `AEAD.Decrypt` - The encryption and decryption functions
  for the AEAD.  We follow the convention of RFC 5116 {{!RFC5116}} and consider
  the authentication tag part of the ciphertext produced by `AEAD.Encrypt` (as
  opposed to a separate field as in SRTP {{?RFC3711}}).

* `AEAD.Nk` - The size in bytes of a key for the encryption algorithm

* `AEAD.Nn` - The size in bytes of a nonce for the encryption algorithm

* `AEAD.Nt` - The overhead in bytes of the encryption algorithm (typically the
  size of a "tag" that is added to the plaintext)

* `AEAD.Nka` - For cipher suites using the compound AEAD described in {{Section
  4.5.1 of RFC9605}}, the size in bytes of a key for the underlying encryption
  algorithm

* `Hash.Nh` - The size in bytes of the output of the hash function

## Metadata Authentication

The KID, track name, group ID, and object ID of the object are authenticated as
part of secure object encryption.  This ensures, for example, that encrypted
objects cannot be replayed across tracks.

When protecting or unprotecting a secure object, an endpoint encodes the key ID,
group ID, object ID, and full track name in the following data structure, for
input to the AEAD function's AAD argument:

``` pseudocode
SECURE_OBJECT_AAD {
    Key ID (i),
    Group ID (i),
    Object ID (i),
    Track Namespace (tuple),
    Track Name (b),
}
```

## Nonce Formation

The group ID and object ID for an object are used to form a 96-bit counter (CTR)
value, which XORed with a salt to form the nonce used in AEAD encryption.  The
counter value is formed by encoding the group ID and object ID as QUIC varints,
then concatenating these representations.  This scheme MUST NOT be applied to an
object where group ID is larger than 2<sup>62</sup> or the object ID is larger
than 2<sup>30</sup>.

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

    group_shift = 96 - group_bits
    object_shift = group_shift - object_bits

    return (group_id << group_shift) | (object_id << object_shift)
```

## Key Derivation

Encryption and decryption use a key and salt derived from the `base_key`
associated with a KID.  Given a `base_key` value, the key and salt are derived
using HMAC-based Key Derivation Function (HKDF) {{!RFC5869}} as follows:

~~~ pseudocode
def derive_key_salt(KID, base_key):
  moq_secret = HKDF-Extract("", base_key)

  moq_key_label = "MOQ 1.0 Secret key " + KID + cipher_suite
  moq_key =
    HKDF-Expand(moq_secret, moq_key_label, AEAD.Nk)

  moq_salt_label = "MOQ 1.0 Secret salt " + KID + cipher_suite
  moq_salt =
    HKDF-Expand(moq_secret, moq_salt_label, AEAD.Nn)

  return moq_key, moq_salt
~~~

In the derivation of `moq_secret`:

* The `+` operator represents concatenation of byte strings.

* The KID value is encoded as an 8-byte big-endian integer.

* The `cipher_suite` value is a 2-byte big-endian integer representing the
  cipher suite in use (see {{I-D.ietf-sframe-enc}}).

The hash function used for HKDF is determined by the cipher suite in use.

## Encryption

MOQT secure object encryption uses the AEAD encryption algorithm for the cipher
suite in use.  The key for the encryption is the `moq_key`.  The nonce is
formed by first XORing the `moq_salt` with the current CTR value, and then
encoding the result as a big-endian integer of length `AEAD.Nn`.

~~~ pseudocode
def encrypt(full_track_name, kid, object):
    # Identify the appropriate encryption context
    ctx = context_for_track(full_track_name)
    moq_key, moq_salt = ctx.key_store[kid]

    # Compute the required CTR parameter
    ctr = encode_ctr(object.group_id, object.object_id)

    # Assemble the AAD value
    aad = encode_aad(kid, ctr, full_track_name)

    # Perform the AEAD encryption
    nonce = xor(moq_salt, ctr)
    encrypted_payload = AEAD.encrypt(moq_key, nonce, aad, object.payload)

    # Assemble the secure object payload
    (encoded_kid, _) = encode_varint(kid)
    object.payload = encoded_kid + encrypted_payload
~~~

## Decryption

The KID field in the secure object payload is used to find the right key and
salt for the encrypted frame, among those defined for the object's track, and
the CTR field is used to construct the nonce. The decryption procedure is
as follows:

~~~ pseudocode
def decrypt(full_track_name, object):
    # Parse the secure object payload
    (kid, kid_byte_len) = parse_varint(object.payload)
    ciphertext = object.payload[kid_byte_len:]

    # Identify the appropriate encryption context
    ctx = context_for_track(full_track_name)
    moq_key, moq_salt = ctx.key_store[kid]

    # Compute the required CTR parameter
    ctr = encode_ctr(object.group_id, object.object_id)

    # Assemble the AAD value
    aad = encode_aad(kid, ctr, full_track_name)

    # Perform the AEAD decryption
    object.payload = AEAD.decrypt(moq_key, nonce, aad, ciphertext)
~~~

If a ciphertext fails to decrypt because there is no key available for the KID
value presented, the client MAY buffer the ciphertext and retry decryption once
a key with that KID is received.  If a ciphertext fails to decrypt for any other
reason, the client MUST discard the ciphertext. Invalid ciphertexts SHOULD be
discarded in a way that is indistinguishable (to an external observer) from
having processed a valid ciphertext.  In other words, the decryption
operation should take the same amount of time regardless of whether decryption
succeeds or fails.

# Security Considerations {#security}

The cryptographic computations described in this document are exactly those
performed in the SFrame encryption scheme defined in {{!I-D.ietf-sframe-enc}},
The scheme in this document is effectively a "virtualized" version of SFrame:

* The CTR value used in nonce formation is not carried in the object payload,
  but instead synthesized from the group ID and object ID.

* The AAD for the AEAD operation is not sent on the wire (as with the SFrame
  Header), but constructed locally by the encrypting and decrypting endpoints.

* The format of the AAD is different:

    * The SFrame Header is constructed using QUIC-style varints, instead of the
      variable-length integer scheme defined in SFrame.

    * The group ID and object ID are sent directly, not as the packed CTR value.

* The `metadata` input in to SFrame operations is defined to be the
  FullTrackName value for the object.

* The labels used in key derivation reflect MOQ usage, not generic SFrame.

The security considerations discussed in the SFrame specification thus also
apply here.

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
   defined in {{metadata-authentication}}.

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
