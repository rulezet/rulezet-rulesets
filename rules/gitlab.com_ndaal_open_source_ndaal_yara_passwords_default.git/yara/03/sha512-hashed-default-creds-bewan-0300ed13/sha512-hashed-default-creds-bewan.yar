rule sha512_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15bcb0aa64587ef8b486b222ba52d7371b873ce5d286706a5305dcd6393ecbba1282ff25c2620d7293335272377dac767c6396fcd1604bb64ae687e8b9c0c1a0"
    $a1="15bcb0aa64587ef8b486b222ba52d7371b873ce5d286706a5305dcd6393ecbba1282ff25c2620d7293335272377dac767c6396fcd1604bb64ae687e8b9c0c1a0"
condition:
    ($a0 and $a1)
}