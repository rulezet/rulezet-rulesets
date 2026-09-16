rule md5_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="854f36c709b662f53c00ea2c11a40f7a"
    $a1="e6489ee7c554faef44dc324e110f3595"
    $a2="6a29cf18161f652ab0e0b2943249c52e"
    $a3="c1174207802b9ac58eacb57e67febb68"
    $a4="7f903d844b517574584c8669a963227f"
    $a5="07b4672c5f1de542c2c3833aa5c6ccc0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}