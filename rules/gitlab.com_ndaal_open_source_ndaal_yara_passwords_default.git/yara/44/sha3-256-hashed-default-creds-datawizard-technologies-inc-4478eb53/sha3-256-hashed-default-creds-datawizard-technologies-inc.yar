rule sha3_256_hashed_default_creds_datawizard_technologies_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizard_technologies_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
    $a1="36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
condition:
    ($a0 and $a1)
}