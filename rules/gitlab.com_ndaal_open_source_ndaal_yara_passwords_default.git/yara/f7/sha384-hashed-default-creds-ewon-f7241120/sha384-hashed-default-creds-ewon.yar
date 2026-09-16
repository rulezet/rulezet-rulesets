rule sha384_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f290520af1f0a7529e696507f69ec5fc3e9b75fe834611ba3fcd82dbb1ccd4ae754a580537baadf97c2db43ed36e07e"
    $a1="1f290520af1f0a7529e696507f69ec5fc3e9b75fe834611ba3fcd82dbb1ccd4ae754a580537baadf97c2db43ed36e07e"
condition:
    ($a0 and $a1)
}