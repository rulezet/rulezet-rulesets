rule sha1_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a32e0a88c1f082a3ab01b7ae773837f140083ba9"
    $a1="d9e8b295d2eb1aa8badfc258482dd064ebf92ff6"
    $a2="ce5831dfec31a90fe7a84444759c4c9c499f1d65"
    $a3="3f8d5bfb7fa75368b10d133fd615c91934b92d73"
    $a4="af04c88eef7d55a2ab7ca2555a1a4e31e25e0224"
    $a5="961398f8244c637b356df3ee9f968d348647f998"
    $a6="350488fdbc51b2886cad9ac8ccb3cb8645f2ed15"
    $a7="d636c59b5c3d7b509bd6c34a0b8d0c3607e9da45"
    $a8="cd95b28596f76196eda1286610d56439f70dd211"
    $a9="cd95b28596f76196eda1286610d56439f70dd211"
    $a10="23e01ff4f8c6bb030580163e6cfa9eeea63a8ad3"
    $a11="23e01ff4f8c6bb030580163e6cfa9eeea63a8ad3"
    $a12="7e0bb7f3ac2d6be75e678cce8288ffeada8194f8"
    $a13="7e0bb7f3ac2d6be75e678cce8288ffeada8194f8"
    $a14="b23abdbfc08e798d808012c78489422516d351ea"
    $a15="b23abdbfc08e798d808012c78489422516d351ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}