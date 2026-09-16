rule sha3_512_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="70ff103a2896a268b929142685f7aff5e30c064ded1519f9d05ddbace488e3d8659f0a9ec917b478f1871f768e7d55685cddecec29d50da14f3793f59b3cee08"
    $a1="70ff103a2896a268b929142685f7aff5e30c064ded1519f9d05ddbace488e3d8659f0a9ec917b478f1871f768e7d55685cddecec29d50da14f3793f59b3cee08"
condition:
    ($a0 and $a1)
}