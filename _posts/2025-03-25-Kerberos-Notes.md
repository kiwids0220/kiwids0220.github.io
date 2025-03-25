---
layout: post
title: Kerberos Study Notes
date: 2025-03-25
categories: [Notes, Kerberos]
tags:
  - notes
---

## Kerberos
[RFC4120](https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.1)

| #         | Description                                                                                         |
|-----------|-----------------------------------------------------------------------------------------------------|
| 1         | AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key (Section 5.2.7.2)          |
| 2         | AS-REP Ticket and TGS-REP Ticket (includes TGS session key or application session key), encrypted with the service key (Section 5.3) |
| 3         | AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key (Section 5.4.2) |
| 4         | TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS session key (Section 5.4.1)         |
| 5         | TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS authenticator subkey (Section 5.4.1)|
| 6         | TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed with the TGS session key (Section 5.5.1)|
| 7         | TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS authenticator subkey), encrypted with the TGS session key (Section 5.5.1) |
| 8         | TGS-REP encrypted part (includes application session key), encrypted with the TGS session key (Section 5.4.2) |
| 9         | TGS-REP encrypted part (includes application session key), encrypted with the TGS authenticator subkey (Section 5.4.2) |
| 10        | AP-REQ Authenticator cksum, keyed with the application session key (Section 5.5.1)                  |
| 11        | AP-REQ Authenticator (includes application authenticator subkey), encrypted with the application session key (Section 5.5.1) |
| 12        | AP-REP encrypted part (includes application session subkey), encrypted with the application session key (Section 5.5.2) |
| 13        | KRB-PRIV encrypted part, encrypted with a key chosen by the application (Section 5.7.1)            |
| 14        | KRB-CRED encrypted part, encrypted with a key chosen by the application (Section 5.8.1)            |
| 15        | KRB-SAFE cksum, keyed with a key chosen by the application (Section 5.6.1)                         |
| 16-18     | Reserved for future use in Kerberos and related protocols                                           |
| 19        | AD-KDC-ISSUED checksum (ad-checksum in 5.2.6.4)                                                     |
| 20-21     | Reserved for future use in Kerberos and related protocols                                           |
| 22-25     | Reserved for use in the Kerberos Version 5 GSS-API mechanisms [RFC4121]                            |
| 26-511    | Reserved for future use in Kerberos and related protocols                                           |
| 512-1023  | Reserved for uses internal to a Kerberos implementation                                             |
| 1024      | Encryption for application use in protocols that do not specify key usage values                   |
| 1025      | Checksums for application use in protocols that do not specify key usage values                    |
| 1026-2047 | Reserved for application use                                                                        |




| Key Usage Number | Description                                                                                 |
|------------------|---------------------------------------------------------------------------------------------|
| 1                | AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key (Section 5.2.7.2)   |
| 2                | AS-REP Ticket and TGS-REP Ticket (includes TGS session key or application session key), encrypted with the service key (Section 5.3) |
| 3                | AS-REP encrypted part (includes TGS session key or application session key), encrypted with the client key (Section 5.4.2) |
| 4                | TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS session key (Section 5.4.1)  |
| 5                | TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with the TGS authenticator subkey (Section 5.4.1) |
| 6                | TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator checksum, keyed with the TGS session key (Section 5.5.1) |
| 7                | TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS authenticator subkey), encrypted with the TGS session key (Section 5.5.1) |
| 8                | TGS-REP encrypted part (includes application session key), encrypted with the TGS session key (Section 5.4.2) |
| 9                | TGS-REP encrypted part (includes application session key), encrypted with the TGS authenticator subkey (Section 5.4.2) |
| 10               | AP-REQ Authenticator checksum, keyed with the application session key (Section 5.5.1)        |
| 11               | AP-REQ Authenticator (includes application authenticator subkey), encrypted with the application session key (Section 5.5.1) |
| 12               | AP-REP encrypted part (includes application session subkey), encrypted with the application session key (Section 5.5.2) |
| 13               | KRB-PRIV encrypted part, encrypted with a key chosen by the application (Section 5.7.1)      |
| 14               | KRB-CRED encrypted part, encrypted with a key chosen by the application (Section 5.8.1)      |
| 15               | KRB-SAFE checksum, keyed with a key chosen by the application (Section 5.6.1)                |
| 16–18            | Reserved for future use in Kerberos and related protocols                                    |
| 19               | AD-KDC-ISSUED checksum (ad-checksum in 5.2.6.4)                                             |
| 20–21            | Reserved for future use in Kerberos and related protocols                                    |
| 22–25            | Reserved for use in the Kerberos Version 5 GSS-API mechanisms [RFC4121]                      |
| 26–511           | Reserved for future use in Kerberos and related protocols                                    |
| 512–1023         | Reserved for uses internal to a Kerberos implementation                                      |
| 1024             | Encryption for application use in protocols that do not specify key usage values             |
| 1025             | Checksums for application use in protocols that do not specify key usage values              |
| 1026–2047        | Reserved for application use                                                                 |

