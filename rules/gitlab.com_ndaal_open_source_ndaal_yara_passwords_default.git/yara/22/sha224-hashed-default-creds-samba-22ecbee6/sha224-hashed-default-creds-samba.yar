rule sha224_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2cdc069c1b6c826781363e8277957d71cf5e8250032d2d80babc7476"
    $a1="2cdc069c1b6c826781363e8277957d71cf5e8250032d2d80babc7476"
condition:
    ($a0 and $a1)
}