rule sha1_hashed_default_creds_yuxin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for yuxin."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a2="1115ec22f30fdbefb28f6dbe259ae75131da8b54"
    $a3="9f8a2389a20ca0752aa9e95093515517e90e194c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}