rule mysql323_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ca052e32963bcfa"
    $a1="43e9a4ab75570f5b"
    $a2="6ca052e32963bcfa"
    $a3="64114f66164c1a64"
    $a4="5193c212068240f0"
    $a5="482165255b529f94"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}