rule sha3_384_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0be128d62f2800d7c12e8c90d361257b3df6638ab81a873d6c095a6357922cb910e3fb506739c6b812a564b49810da"
    $a1="428b7583e7ccbd3ead41157bf93e56ef8ff8eb6131aced0d046f9750a131eb5477dff3e7acdc65446d2f06a53a943d8a"
    $a2="3b29171c283a0b18aae5868de7d876dbd3246f55a1855fabac4d247425f50f1f41617cadae253f6546b8eadfa8d10755"
    $a3="3b29171c283a0b18aae5868de7d876dbd3246f55a1855fabac4d247425f50f1f41617cadae253f6546b8eadfa8d10755"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}