rule mysql323_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="16d7f906289d77b3"
    $a1="43e9a4ab75570f5b"
    $a2="3bddeb931f8eeede"
    $a3="5ae13bf65efb4e4b"
    $a4="2589c6b11a5f226a"
    $a5="7edb51880433a2b9"
    $a6="16d7f906289d77b3"
    $a7="7b11c80522accf00"
    $a8="4217c78666f07ecb"
    $a9="2deff7b92004fc45"
    $a10="765d8c050dca2c7b"
    $a11="57217c04615a3276"
    $a12="78b91e8c2868f026"
    $a13="67457e226a1a15bd"
    $a14="16d7f906289d77b3"
    $a15="67457e226a1a15bd"
    $a16="67cd04f17742d92e"
    $a17="0f68a4ec5ff09f3d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}