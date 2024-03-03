---
title: Secure Objects for Media over QUIC
abbrev: SecureObject
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
mechanism for application objects intended to be delivered over Media
over QUIC Transport (MOQT).

--- middle


# Introduction

Media Over QUIC Transport (MOQT) is a protocol that is optimized for the
QUIC protocol, either directly or via WebTransport, for the
dissemination of delivery of low latency media. MOQT defines a
publish/subscribe media delivery layer across set of participating
relays for supporting wide range of use-cases with different resiliency
and latency (live, interactive) needs without compromising the
scalability and cost effectiveness associated with content delivery
networks. It supports sending media objects through sets of relays
nodes.

Typically a MOQ Relay doesn't need to access the media content, thus
allowing for the media to be "end-to-end" encrypted so that it cannot be
decrypted by the relays. However for the relays to participate
effectively in the media delivery, it needs to able to access naming
information of a MOQT object to carryout the required store and forward
functions.

As such, two layers of encryption and authentication are required:

- Hop-by-hop (HBH) encryption achieved through QUIC connection per hop
  and

- End-to-end (E2E) encryption (E2EE) of media between the endpoints.

The HBH security is provided by TLS in the QUIC connection that MoQT
runs over. MoQT support different E2EE protection as well as allowing
for E2EE security.

A goal of the design is to minimize the amount of additional data the
encryptions requires for each object. This is particularly important for
very low bit rate audio applications where the encryption overhead can
become a significant portion of the total bandwidth.

This document defines an E2EE protection scheme known as Secure Object.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
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
: Software that creates and encrypts MoQ Objects.

Consumer:
: Software that decrypts MoQ Objects.

# MOQT Object Model Recap

MOQT defines a publish/subscribe based media delivery protocol, where in
endpoints, called producers, publish objects which are delivered via
participating relays to receiving endpoints, called consumers.

Section 2 of MoQ Transport defines hierarchical object model for
application data, comprised of objects, groups and tracks.

Objects defines the basic data element, an addressable unit whose
payload is sequence of bytes. All objects belong to a group, indicating
ordering and potential dependencies. A track contains a sequence of
groups and serves as the entity against which a consumer issues a
subscription request.

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

Objects are comprised of two parts: envelope and a payload. The envelope
is never end to end encrypted and is always visible to relays. The
payload portion may be end to end encrypted, in which case it is only
visible to the producer and consumer. The application is solely
responsible for the content of the object payload.

Tracks are identified by a combination of its `TrackNamespace ` and
`TrackName`.  TrackNamespace and TrackName are treated as a sequence of
binary bytes.  Group and Objects are represented as variable length
integers called GroupId and ObjectId respectively.

For purposes of this specification, we define `FullTrackName` as :

~~~
FullTrackName = TrackNamespace | TrackName
~~~
where '|' representations concatenation of byte strings,

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


# Secure Object

This document defines an encryption mechanism, called Secure
Object(SecObj), that provides effective E2EE protection with a minimal
encryption bandwidth overhead.

SecObj encryption uses an AEAD function {{!RFC5116}} defined by the
cipher suite in use (see {{cipher-suites}}).

We will refer to the following aspects of the AEAD algorithm below:

AEAD.Encrypt and AEAD.Decrypt - The encryption and decryption functions
for the AEAD.

AEAD_KEY_SIZE: The size in bytes of a key for the encryption algorithm

AEAD_NONCE_SIZE: The size in bytes of a nonce for the encryption
algorithm

AEAD_TAG_SIZE: The overhead in bytes of the encryption algorithm
          (typically the size of a "tag" that is added to the plaintext)


An SecObj cipher text comprises an header, followed by output of an AEAD
encryption of the plaintext {{!RFC5116}} corresponding to the MOQT
Object.  The header consists of a variable length encoded integer called
KID.


## Keys, Salts, and Nonces

When encrypting objects within a MOQT Track, there is one secret called
`track_base_key` per `FullTrackName` on which is premised the encryption
or decryption operations for the objects within that track.

In MoQ, for some use cases, like streaming a video clip, all the objects
in a track will often be encrypted with the same base key for that
track.  However in other uses cases, like a conference call, the keys
may change as the participants of the conference come and go. For this
type of scenario, different object in the same track will end up being
protected with different base keys. Each encrypted object also carries
an unencrypted "Key Identifier (KID)" which is a small integer that
identifies, within the scope of this track, the base key being used to
encrypt the object. The actual keys for each KID and FullTrackName are
exchanged between the devices encrypting and decrypting in ways that are
out of scope of this specification.

The producers and consumers need to agree on which key should be used
for a given KID and the purpose of the key, encryption or decryption
only. A given key MUST NOT be used for encryption by multiple senders
unless it can be ensured that nonce isn't reused.  Sine such reuse would
result in multiple encrypted objects being generated with the same (key,
nonce) pair, which harms the protections provided by many AEAD
algorithms.  MoQ does not allow two different objects to have the same
FullObjectName so the way the nonce is generated ( see section TODO )
protects against NONCE reuse. Implementations SHOULD mark each key as
usable for encryption or decryption.

## Key Derivation {#key-derivation}

Secobj encryption and decryption use a key and salt derived from the
`track_base_key` associated to a KID.  Given a `track_base_key` value
for a `FullTrackName` the key and salt are derived using HKDF
{{!RFC5869}} as follows:

~~~~~
  secobj_label = "SecObj 1.0"
  secobj_secret = HKDF-Extract(secobj_label, track_base_key)

  secobj_key_label = "SecObj 1.0 Secret key" | KID | cipher_suite | FullTrackName
  secobj_key = HKDF-Expand(secobj_secret, secobj_key_label, AEAD_KEY_SIZE)

  secobj_salt_label = "SecObj 1.0 Secret salt" | KID | cipher_suite
  secobj_salt = HKDF-Expand(secobj_secret, secobj_salt_label, AEAD_NONCE_SIZE)
~~~~~

In the above derivation :

* The `|` operator represents concatenation of byte strings.

* The `cipher_suite` value is a 16 bit big-endian integer representing the
  cipher suite in use (see cipher-suites).

* The KID is a 64 bit big-endian integer.

The hash function used for HKDF is determined by the cipher suite in use.

## Encryption

The key for encrypting MOQT objects from a given track is the
`secobj_key` derived from the track_base_key {{key-derivation}}
corresponding to the track.

The Nonce is formed by XORing the `secobj_salt` {{key-derivation}} with
bits from the GroupId | ObjectId, where both the GroupId and ObjectId
are treated as 48 bit big-endian integer. Both the ObjectID and GroupID
MUST be less than 2^48-1. The N_MIN from the AEAD cipher MUST be at
least 12 to have space for the object and group IDs to fit in the
nonce. Note that the size of the nonce is defined by the underlying AEAD
algorithm in use but for the algorithm referenced here, it is 12 octets.

The encryptor forms an SecObj header using the KID value provided.

The AAD data is formed by concatinating the SecObj Header, GroupID, and
ObjectID.  The payload field from the MOQT object is used by the AEAD
algorithm for the plaintext.

The final SecureObject is formed from the SecObject Header, follow by the
MOQT transport headers, followed by the output of the encryption.

Below figure depicts the encryption process described

~~~~~

                                  +----------------+
                                  |                |
        +-------------------------|      MOQT      |
        |                  +------|     Object     |
        |                  |      |                |
        |                  |      +--------+-------+
        |                  |                |
        |                  |                |
        |                  |                |
        |                  |                |
        |                  | FullTrackName  |
+----------------+         | (from          |
|    GroupId     |         | track_alias)   |
+----------------+         |                |
|  Object ID     |         |                |
+----------------+         |                |
|        |             +------------+       |
|<-------|-----------  |    KID     |       | Object
|        |<------------|            |       | Payload
|        |             +------------+       |
|        |  secobj_salt      |              |
|        |                   |              |
|        |                   |              |
|        v                   | secobj_key   |
|  +-----------+             |              |
|  |  NONCE    |             |              |
|  +-----------+             |              |
|        |                   |              |
|        |                   v              |
|        |           +--------------+       |
|        |           |              |       |
|        +---------->| AEAD.Encrypt |<------+
+------------------->|              |
    AAD              +-------+------+
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

## Decryption

For decrypting, the KID field in the SecObj header is used to find the
right key and salt for the encrypted object, and the nonce field is
obtained from the `GroupId` and `ObjectId` fields of the MOQT object
envelope. The decryption procedure is as follows:

1. Parse the SecureObject to obtain KID from the SecObj header, the
ciphertext corresponding to the MOQT object payload and Group and
ObjectId from the MOQT object envelope.

2. Retrieve the `secobj_key` and `secobj_salt` matching the KID.

3. Form the nonce by XORing secobj_salt, the bits from `GroupID |
ObjectId` encoded as big-endian integer.

4. From the aad input by bitwse concatenating SecObj header with the
Group and the ObjectId fields.

Apply the decryption function with secobj_key, nonce, aad and ciphertext
as inputs.

If a ciphertext fails to decrypt because there is no key available for
the KID in the SecObj header, the client MAY buffer the ciphertext and
retry decryption once a key with that KID is received.  If a ciphertext
fails to decrypt for any other reason, the client MUST discard the
ciphertext. Invalid ciphertext SHOULD be discarded in a way that is
indistinguishable (to an external observer) from having processed a
valid ciphertext.

Below figure depicts the decryption process:

~~~~~


                                    SecObj CipherText

                                    +--------------+
+-----------------------------------|    KID       |
|                                   +--------------+
|                                   |              |
|          +------------------------| CipherText   |
|          |                  +-----|              |
|          |                  |     +--------------+
|          |                  |              |
|          |                  |              |
|          |                  |              |
|          |                  |              |
|          |                  |              |
|          v                  |              |
|  +----------------+         | KID          |
|  |    GroupId     |         |              |
|  +----------------+         |              |
|  |  Object ID     |         |              |
|  +----------------+         |              |
|  |      |                    v             |
|  |      |               +------------+     |
|  |      |<--------------|  KeyStore  |     | ciphertext
|  |      |               +------------+     |
|  |      |  secobj_salt        |            |
|  |      |                     |            |
|  |      |                     |            |
|  |      v                     | secobj_key |
|  | +-----------+              |            |
|  | |  NONCE    |              |            |
|  | +-----------+              |            |
|  |      |                     |            |
|  |      |                     v            |
|  |      |             +--------------+     |
|  |      |             |              |     |
|  |      +------------>| AEAD.Decrypt |<------+
|  +------------------->|              |
|          ^   AAD      |              |
|          |            +-------+------+
+----------+                   |
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

## SecObj Cipher Suites {#cipher-suites}

This registry lists identifiers for SecObj cipher suites, as defined in
cipher-suites.  The cipher suite field is two bytes wide, so the valid
cipher suites are in the range 0x0000 to 0xFFFF. Values less that 128
are allocated by "IESG Approval" (ref rfc8126) while others values are
"First Come First Served".

Template:

* Value: The numeric value of the cipher suite

* Name: The name of the cipher suite

* Tag Length: Length of tag in bits

* Usage: Optional, Recommended, or Prohibited

* Reference: The document where this wire format is defined


Initial contents:


| Value  | Name                          | Tag | Usage |  Reference |
|:-------|:------------------------------|----:|:------|:-----------|
| 0x0001 | `AES_128_GCM_SHA256_128`      | 128 | Recommended| RFC XXXX  |
| 0x0002 | `AES_256_GCM_SHA512_128`      | 128 | Optional | RFC XXXX  |
{: #iana-cipher-suites title="SecObj cipher suites" }


--- back

# Acknowledgements

TODO
