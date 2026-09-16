rule sha384_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d55914d9b903bccac281e27932575a1b44e03aaa62dcf3a965c5c47bc528a707b7281620812451cd04802d749cf6d385"
    $a1="5ab17954fa5805a49d61b74f9cd402a4391438da77b04690175d423a018331d7dd93c0fa53daf525a53d5a97b7e913ae"
condition:
    ($a0 and $a1)
}