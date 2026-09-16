rule blake2s_hashed_default_creds_vpasp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for vpasp."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="4168e1ea29569d37f24b66876d5b53831ad060dafb3f06dcb451fccf2015375b"
    $a3="4168e1ea29569d37f24b66876d5b53831ad060dafb3f06dcb451fccf2015375b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}