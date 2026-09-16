rule blake2s_hashed_default_creds_ubiquiti_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
    $a5="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}