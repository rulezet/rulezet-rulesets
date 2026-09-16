rule blake2s_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="832fa1c2c0abfd5539261cb7d3c0c4f0ecd1703a293f360e8d4be65b980f667c"
    $a1="832fa1c2c0abfd5539261cb7d3c0c4f0ecd1703a293f360e8d4be65b980f667c"
condition:
    ($a0 and $a1)
}