rule sha3_384_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
    $a1="e7322badae51ef5cc2401b9ad02938bd77b14d13a6ee75cc7076c8104f83d64392ee5de9157839556dce80246fd7fb6b"
condition:
    ($a0 and $a1)
}