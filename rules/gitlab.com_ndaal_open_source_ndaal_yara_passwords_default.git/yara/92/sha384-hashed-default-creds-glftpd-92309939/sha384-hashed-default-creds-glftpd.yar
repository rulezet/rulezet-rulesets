rule sha384_hashed_default_creds_glftpd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for glftpd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0011829e5362892111f498c20efa1fab746af43c3fd27256abf6b453f979fe7e4b822d9aefceecc8e931c6b8c3a47d52"
    $a1="0011829e5362892111f498c20efa1fab746af43c3fd27256abf6b453f979fe7e4b822d9aefceecc8e931c6b8c3a47d52"
condition:
    ($a0 and $a1)
}