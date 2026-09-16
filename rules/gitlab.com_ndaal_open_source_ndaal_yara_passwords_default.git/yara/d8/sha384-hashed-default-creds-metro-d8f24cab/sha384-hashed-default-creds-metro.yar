rule sha384_hashed_default_creds_metro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metro."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
    $a1="dccfe25e8c0d8b5b355fe1e715f466b3e7027be30acbf965f4e6160045ea11a6d871190306f00fbabd09931a2a0bea2e"
condition:
    ($a0 and $a1)
}