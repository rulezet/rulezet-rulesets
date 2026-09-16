rule sha384_hashed_default_creds_bni
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bni."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
    $a1="8b7d7cc6f927b7040e35cb0a33d70e264c7317e4e2079517a1c636e588121efec3ba9be57c92a929957e7fa5e8e33f78"
condition:
    ($a0 and $a1)
}