rule sha224_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79f95ce631a460dc2e3d220a5dffbb5616074375648e4a2212127ecf"
    $a1="f0eedf23e47ac86859d4b99acd76f763dedb98933915e927c3d5414d"
condition:
    ($a0 and $a1)
}