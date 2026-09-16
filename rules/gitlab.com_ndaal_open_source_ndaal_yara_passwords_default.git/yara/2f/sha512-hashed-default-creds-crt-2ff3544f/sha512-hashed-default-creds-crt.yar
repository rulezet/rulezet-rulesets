rule sha512_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b515a451324ff35cd55224f390cad6f1d9606c3678e164eeae19875b5444f9c3feefc792b02edb1b8c9b73e90964b484febc51650b2513aa4d99a48b5f0616a6"
    $a1="831baff160a608ef921ade3231a30d1f3d7a87f0919e20d84800be442f72e8b850e8d9af9b18e4f98f63f7d8594ebc04311d158159d6ea661f49c2a950504368"
condition:
    ($a0 and $a1)
}