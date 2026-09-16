rule sha3_384_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
    $a5="118255d8ecf3afde0a9c33214f4d65fa2fe3eba96c12ba7f92d676e067d2b01a573ed43b751b84abf8da2d5a8253984d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}