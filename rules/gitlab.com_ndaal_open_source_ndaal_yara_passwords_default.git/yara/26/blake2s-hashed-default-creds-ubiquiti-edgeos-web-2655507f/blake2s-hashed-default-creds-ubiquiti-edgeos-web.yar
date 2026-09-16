rule blake2s_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
    $a1="a70406d9a492442497b7e3d9f89487d6ab15c8eb14cdcf3e9512fe26157004ac"
condition:
    ($a0 and $a1)
}