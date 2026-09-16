rule sha3_384_hashed_default_creds_zyxel_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e4eebde2872cc827253b095351ff431bce62c6207c0886354b53fb660f1a0b566f05afe3de0b1d31deccd9bfc7a9dfc"
    $a1="59e8791b3c6afcaed93cca20f50282848687f5f037287d8510e2a04e30c41c4d1133066dc1382b1c21e8ee0edf9f0dd4"
condition:
    ($a0 and $a1)
}