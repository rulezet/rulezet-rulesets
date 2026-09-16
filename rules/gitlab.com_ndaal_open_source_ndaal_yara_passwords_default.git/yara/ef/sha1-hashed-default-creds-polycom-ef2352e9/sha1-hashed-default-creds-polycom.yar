rule sha1_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a1="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a2="264cdbe779c23de98fb932498d2a6222524ac6a8"
    $a3="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a4="5436b8cd6b2498de3d1986a71b0c759005258859"
    $a5="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a6="fec4af4d9874274f99450a11028613ef8b3a8a69"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="f7ec3371c582972b154770dce9d85e2fc60fa4ab"
    $a9="b0c4f366f1d1f950d3e4a48e67dd84e893a71e50"
    $a10="51eac6b471a284d3341d8c0c63d0f1a286262a18"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}