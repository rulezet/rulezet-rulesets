rule sha1_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb2237d0679ca88db6464eac60da96345513964"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="8cb2237d0679ca88db6464eac60da96345513964"
    $a3="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a4="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="7c4a8d09ca3762af61e59520943dc26494f8941b"
    $a7="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}