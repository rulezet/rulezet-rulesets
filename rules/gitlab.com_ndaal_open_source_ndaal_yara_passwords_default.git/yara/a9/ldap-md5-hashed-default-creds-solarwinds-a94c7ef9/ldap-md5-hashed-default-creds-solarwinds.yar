rule ldap_md5_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}EYH/r7ti2x4Yk2p0Q+cTqg=="
    $a1="{MD5}4jY5PUn+MSdVkPTRWcwPFQ=="
    $a2="{MD5}Ss+VQRnVv4wO9c4H85be+w=="
    $a3="{MD5}Ss+VQRnVv4wO9c4H85be+w=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}