rule sha3_384_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5b1b0af242b690c3b681ad8e1c0c8d202504fcdd7f041b86d0b1cd54eb04e03c069f8cc5e1817e43c4b2a387691904e7"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="2fec206acf134425d44d35ad36d00a24cab7fca41de03ba021415dc11da227477cc71c8e5179ca067a7db0889fb84766"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a5="d1ead38489a10222f7aecbf07399721e4d243c8e56fcb0a780b966f905a1d4165402284b852bdcd046a193ff6fb0e519"
    $a6="1f9c692c2766f2abbee9a8e26e5e3fc0b9fdbb721ccd67bb333078eabbcb8e680eb4f8a8c2cbd5fe8d17390a7eb358e1"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}