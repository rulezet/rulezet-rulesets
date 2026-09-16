rule sha3_224_hashed_default_creds_tert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tert."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c08c456cda7d5743cb89daf81d5a58b846fa0067a11635ec010602a7"
    $a1="c08c456cda7d5743cb89daf81d5a58b846fa0067a11635ec010602a7"
condition:
    ($a0 and $a1)
}