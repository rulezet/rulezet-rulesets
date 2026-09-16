rule sha1_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ceac9075d299cc3759efc61e1ae315c294076f7f"
    $a1="ceac9075d299cc3759efc61e1ae315c294076f7f"
    $a2="f4c620a95656b2d7b8c0fed7603ed64bc02cc952"
    $a3="f4c620a95656b2d7b8c0fed7603ed64bc02cc952"
    $a4="8d4d8dd73d5f1d404d25dd30db25d91b8aece276"
    $a5="8d4d8dd73d5f1d404d25dd30db25d91b8aece276"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}