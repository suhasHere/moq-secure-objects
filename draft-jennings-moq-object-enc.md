---
title: SecureObject - An E2E Object Protection Scheme for MOQ
abbrev: SecureObject
docname: draft-jennings-moq-object-enc-latest
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
  github: "moq-wg/moqtransport"
  latest: "https://sframe-wg.github.io/sframe/draft-ietf-sframe-enc.html"

author:
 -
    ins: C. Jennings
    name: Cullen Jennings
    organization: Cisco
    email: fluffy@cisco.com
 -
    ins: S. Nandakumar
    name: Suhas Nandakumar
    organization: Cisco
    email: snandaku@cisco.com


normative:

informative:


--- abstract

This document describes end-to-end encryption and authentication
mechanism for application objects intended to be delivered
over Media over QUIC Transport (MOQT).

--- middle


# Introduction

Media Over QUIC Transport (MOQT) is a protocol that is optimized for the QUIC protocol, either directly or via WebTransport, for the dissemination of media. MOQT defines a publish/subscribe media delivery layer across set of participating relays for supporting wide range of use-cases with different resiliency and latency (live, interactive) needs without compromising the scalability and cost effectiveness associated with content delivery networks.

Typically a MOQ Relay doesn't need to access the media content, thus allowing
for the media to be "end-to-end" encrypted so that it cannot be decrypted by the relays. However for the relays to participate effectively in the media delivery,
it needs to able to access metadata of a MOQT object to carryout the
required store and forward functions.

As such, two layers of encryption and authentication are required:

- Hop-by-hop (HBH) encryption achieved through QUIC connection per hop and
- End-to-end (E2E) encryption (E2EE) of media between the endpoints.

This document proposes a E2EE protection scheme known as moq-enc, an object level
protection scheme designed to work in settigns where MOQT based media delivery is anticipated.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals, as shown here.

IV:
: Initialization Vector

MAC:
: Message Authentication Code

E2EE:
: End to End Encryption

HBH:
: Hop By Hop

Producer:
: Fill in

Consumer:
: Fill in

# MOQT Object Model Recap

MOQT defines a publish/subscribe based media delivery protocol, where in
endpoints, called producers, publish objects which are delivered via
participating relays to receiving endpoints, called consumers.

Section 2 of MoQTransport defines hierarchical object model for
application data, comprised of objects, groups and tracks.

Objects defines the basic data element, an addressable unit whose payload
is sequence of bytes. All objects belong to a group, indicating ordering
and potential dependencies. A track contains a sequence of groups and
serves as the entity against which a consumer issues a subscription request.

~~~~~
  Media Over QUIC Application


          |                                                       time
          |
 TrackA   +-+---------+-----+---------+--------------+---------+---->
          | | Group1  |     | Group2  |  . . . . . . | GroupN  |
          | +----+----+     +----+----+              +---------+
          |      |               |
          |      |               |
          | +----+----+     +----+----+
          | | Object0 |     | Object0 |
          | +---------+     +---------+
          | | Object1 |     | Object1 |
          | +---------+     +---------+
          | | Object2 |     | Object2 |
          | +---------+     +---------+
          |      .
          |      .
          |      .
          | +---------+
          | | ObjectN |
          | +---------+
          |
          |
          |
          |                                                       time
          |
 TrackB   +-+---------+-----+---------+--------------+---------+---->
          | | Group1  |     | Group2  | . . .. .. .. | GroupN  |
          | +---+-----+     +----+----+              +----+----+
          |     |                |                        |
          |     |                |                        |
          |+----+----+      +----+----+              +----+----+
          || Object0 |      | Object0 |              | Object0 |
          |+---------+      +---------+              +---------+
          |
          v


~~~~~

Objects are comprised of two parts: metadata and a payload. The metadata is
never end to end encrypted and is always visible to relays. The payload
portion may be end to end encrypted, in which case it is only visible to the
producer and consumer. The application is solely responsible for the content
of the object payload.

Tracks are identified by a combination of its `TrackNamespace ` and `TrackName`.
Group and Objects are represented as varibale length integers called GroupId and
ObjectId respectively. GroupId and ObjectId increase monotonically for tracks
that are actively publishing media.

For purposes of this specification, we define `FullTrackName` as :

~~~
FullTrackName = TrackNamespace + TrackName
~~~

and  "MOQT Object Name" or "Object Name" is combination of following properties:

~~~
MOQTObjectName = (FullTrackName, GroupId, ObjectId)
~~~

## Requirements

Applications using MOQT for their media delivery MUST ensure the following
requirements are enforced to meet the security assurances from the
protection mechanisms defined in this specification:

- A given `FullTrackName` MUST uniquely identify a single producer within a MOQT Session.

- `GroupId` MUST NOT be duplicated within a Track.

- `ObjectId` MUST NOT be duplicated within a group.


# Secure Object

This document defines an encryption mechanism, called SecureObject(SecObj),
that provides effective E2EE protection with a minimal encryption bandwidth
overhead.

SecObj encryption uses an AEAD encryption algorithm and hash function
defined by the cipher suite in use (see cipher-suites).

We will refer to the following aspects of the AEAD algorithm below:

AEAD.Encrypt and AEAD.Decrypt - The encryption and decryption functions for the AEAD.

AEAD.Nk - The size in bytes of a key for the encryption algorithm

AEAD.Nn - The size in bytes of a nonce for the encryption algorithm

AEAD.Nt - The overhead in bytes of the encryption algorithm
          (typically the size of a "tag" that is added to the plaintext)


An SecObj ciphertext comprises an header, followed by output of an AEAD
encryption of the plaintext {{!RFC5116}} corresponding to the MOQT Object.
The header consists of a variable length encoded integer called KID.


## Keys, Salts, and Nonces

When encrypting objects within a MOQT Track, there is one secret called
`base_key` per `FullTrackName` on which is premised the encryption or
decryption operations for the objects within that track.

The `base_key` is labeled with an integer KID value signaled in the SecObj
header. The producers and consumers need to agree on which key should be used
for a given KID and the purpose of the key, encryption or decryption only.
The process for provisioning keys and their KID values is beyond the scope of
this specification, but its security properties will bound the assurances
that SecObj provides.

A given key MUST NOT be used for encryption by multiple senders unles it can
be ensured that nonce isn't reused.  Sine such reuse would result in multiple
encrypted objects being generated with the same (key,
nonce) pair, which harms the protections provided by many AEAD algorithms.
Implementations SHOULD mark each key as usable for encryption or decryption,
never both.

### Key Derivation {#key-derivation}

Secobj encryption and decryption use a key and salt derived from the `base_key`
associated to a KID.  Given a `base_key` value for a `FullTrackName` the key
and salt are derived using HKDF {{!RFC5869}} as follows:

~~~~~
def derive_key_salt(KID, FullTrackName, base_key):
  secobj_label = "SecObj 1.0 "
  secobj_secret = HKDF-Extract(secobj_label, base_key)

  secobj_key_label = "SecObj 1.0 Secret key " + KID + FullTrackName + cipher_suite
  secobj_key = HKDF-Expand(secobj_secret, secobj_key_label, AEAD.Nk)

  secobj_salt_label = "SecObj 1.0 Secret salt " + KID + cipher_suite
  secobj_salt = HKDF-Expand(secobj_secret, secobj_salt_label, AEAD.Nn)

  return secobj_key, secobj_salt
~~~~~

In the derivation of `secobj_secret`:

* The `+` operator represents concatenation of byte strings.

* The `cipher_suite` value is a 2-byte big-endian integer representing the
  cipher suite in use (see cipher-suites).

The hash function used for HKDF is determined by the cipher suite in use.

### Encryption

The key for encrypting MOQT objects from a given track is the `secobj_key`
derived from the `base_key` {{key-derivation}} corresponding to the track
and the Nonce is formed by XORing the `secobj_salt` {{key-derivation}} with
composition of bits from the object's GroupId and the ObjectId fields,
as a big-endian integer of length `AEAD.Nn`.

The encryptor forms an SecObj header using the KID value provided.
The encoded header along with Nonce is provided as AAD to the AEAD
encryption operation, together with optional application-provided metadata
which would be benefitted from the end to  end authentication about the
encrypted media (see {{metadata}}).

The plaintext corresponds to the payload field of the MOQT Object.

~~~~~
def encrypt(Nonce, KID, metadata, plaintext):
  secobj_key, secobj_salt = key_store[KID]

  Nonce = encode_big_endian(Nonce, AEAD.Nn)
  nonce = xor(secobj_salt, Nonce)

  header = encode_header(KID)

  ciphertext = AEAD.Encrypt(secobj_key, nonce, aad, plaintext)
  return header + ciphertext
~~~~~


~~~~~

                                  +----------------+
                                  |                |
        +-------------------------|      MOQ       |
        |                  +------|     Object     |
        |                  |      |                |
        |                  |      +--------+-------+
        |                  |               |
        |                  |               |
        |                  |               |
        |                  |               |
        |                  | Full          |
+----------------+         |Track          |
|    GroupId     |         | Name          |
+----------------+         |               |
|  Object ID     |         |               |
+----------------+         |               |
        |                  |               |
        |             +------------+       |
        |<------------|    KID     |       |
        |              ------------+       |
        |  secobj_salt      |              |
        |                   |              |
        |                   |              |
        v                   | secobj_key   |
  +-----------+             |              |
  |  NONCE    |             |              |
  +-----------+             |              |
        |                   |              |
        |                   v              |
        |           +--------------+       |
        |           |              |       |
        +---------->| AEAD.Encrypt |<------+
                    |              |
                    +-------+------+
                            |
                            |
                            |
                            v
                    +--------------+
                    |    KID       |
                    +--------------+
                    |              |
                    | CipherText   |
                    |              |
                    +--------------+

                    SecObj CipherText


~~~~~
{: title="Encrypting a MOQT Object Ciphertext" }

### Decryption

For decrypting, the KID field in the SecObj header is used to find the
right key and salt for the encrypted object, and the Nonce field is obtained
from the `GroupId` and `Object` fields of the MOQT object metadata. The
decryption procedure is as follows:

~~~~~
def decrypt(Nonce, secobj_ciphertext):
  KID, ciphertext = parse_ciphertext(secobj_ciphertext)

  secobj_key, secobj_salt = key_store[KID]

  ctr = encode_big_endian(Nonce, AEAD.Nn)
  nonce = xor(secobj_salt, ctr)
  aad = header + metadata

  return AEAD.Decrypt(secobj_key, nonce, aad, ciphertext)
~~~~~

If a ciphertext fails to decrypt because there is no key available for the KID
in the SecObj header, the client MAY buffer the ciphertext and retry decryption
once a key with that KID is received.  If a ciphertext fails to decrypt for any
other reason, the client MUST discard the ciphertext. Invalid ciphertexts SHOULD be
discarded in a way that is indistinguishable (to an external observer) from having
processed a valid ciphertext.

~~~~~


                                    SecObj CipherText

                                   +--------------+
                                   |    KID       |
                                   +--------------+
                                   |              |
        +------------------------- | CipherText   |
        |                  +------ |              |
        |                  |       +--------------+
        |                  |               |
        |                  |               |
        |                  |               |
        |                  |               |
        |                  |               |
        v                  |               |
+----------------+         | KID           |
|    GroupId     |         |               |
+----------------+         |               |
|  Object ID     |         |               |
+----------------+         |               |
        |                  v               |
        |             +------------+       |
        |<------------|    KID     |       |
        |              ------------+       |
        |  secobj_salt      |              |
        |                   |              |
        |                   |              |
        v                   | secobj_key   |
  +-----------+             |              |
  |  NONCE    |             |              |
  +-----------+             |              |
        |                   |              |
        |                   v              |
        |           +--------------+       |
        |           |              |       |
        +---------->| AEAD.Decrypt |<------+
                    |              |
                    +-------+------+
                            |
                            |
                            |
                            v
                    +----------------+
                    |                |
                    |      MOQ       |
                    |     Object     |
                    |                |
                    +----------------+

~~~~~
{: title="Decrypting an MOQT Object Ciphertext" }



# Security Considerations
TODO

# IANA Considerations

## SecObj Cipher Suites

This registry lists identifiers for SecObj cipher suites, as defined in cipher-suites.  The cipher suite field is two bytes wide, so the valid cipher suites are in the range 0x0000 to 0xFFFF.

Template:

* Value: The numeric value of the cipher suite

* Name: The name of the cipher suite

* Reference: The document where this wire format is defined

Initial contents:


| Value  | Name                          | Reference |
|:-------|:------------------------------|:----------|
| 0x0001 | `AES_128_CTR_HMAC_SHA256_80`  | RFC XXXX  |
| 0x0002 | `AES_128_CTR_HMAC_SHA256_64`  | RFC XXXX  |
| 0x0003 | `AES_128_CTR_HMAC_SHA256_32`  | RFC XXXX  |
| 0x0004 | `AES_128_GCM_SHA256_128`      | RFC XXXX  |
| 0x0005 | `AES_256_GCM_SHA512_128`      | RFC XXXX  |
{: #iana-cipher-suites title="SecObj cipher suites" }


--- back

# Acknowledgements

