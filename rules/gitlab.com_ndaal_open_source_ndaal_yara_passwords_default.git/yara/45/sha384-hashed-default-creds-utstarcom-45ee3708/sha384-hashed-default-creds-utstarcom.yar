rule sha384_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="695878b49e5c6b7ab50e8fe214ec1b8b1499dba682161b658f8f57527fb72bfb1d1768eebad0f95e5a6dd9e181432f9d"
    $a1="695878b49e5c6b7ab50e8fe214ec1b8b1499dba682161b658f8f57527fb72bfb1d1768eebad0f95e5a6dd9e181432f9d"
    $a2="50fd6502596b429a798e5bc2344b77781a00eac366bfaecd2eb0795423fe79aa4aaef05d0a0e61c127bb3956e83b784e"
    $a3="4cb32fe7431290f83d82c6699d98e45f824435896266cfa19d53479fda2235503ca178263b8d47e43e3a435dcc5a520b"
    $a4="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a5="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a6="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
    $a7="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}