rule mysql323_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="60671ccd6665c43e"
    $a1="43e9a4ab75570f5b"
    $a2="60671c896665c3fa"
    $a3="5645422074187733"
    $a4="60671ccd6665c43e"
    $a5="642d7f6b5c6185eb"
    $a6="60671b456665c0b6"
    $a7="2c02c83c7dab66f7"
    $a8="606719656665bed6"
    $a9="384c10073d090744"
    $a10="606719b96665bf2a"
    $a11="518b20ae7a2bc49b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}