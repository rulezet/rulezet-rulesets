rule sha3_384_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7b69d913f823eb310165402b8102b5d589f41435e64936b7e7fe899386aa29df4a6423eb73445194d5ba3b5b7c623b7"
    $a1="26b96a280c54b03133b7821eaa1c34b289d8cf6ae0081fb4b694d030016249f159acba3c64ffc8eb8ac10c63bbe37236"
condition:
    ($a0 and $a1)
}