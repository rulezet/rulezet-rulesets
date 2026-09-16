rule nthash_hashed_default_creds_saf_tehnika
{
    meta:
        id = "6YwCkaUFZfnUZQQQI1lTGS"
        fingerprint = "41afdef0b1d7364d9cb8834871a407bae47d09019f91e7c94569aa9a31163acb"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4042f6ed4c7e98dcbff6146ae7ae91d"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
    $a2="40ae60d588a54a222b0d3a4f2e42e956"
    $a3="b4fb4281f46db3a92ac702d2689e044e"
    $a4="3b6be948d1d1b370bdefe5d6c74142a6"
    $a5="3b6be948d1d1b370bdefe5d6c74142a6"
    $a6="0540e95e06bafeaee28aa8c8278ce77f"
    $a7="e337e31aa4c614b2895ad684a51156df"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}