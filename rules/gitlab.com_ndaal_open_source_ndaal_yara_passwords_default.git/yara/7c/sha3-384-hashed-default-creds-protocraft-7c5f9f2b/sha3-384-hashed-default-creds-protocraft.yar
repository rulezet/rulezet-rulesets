rule sha3_384_hashed_default_creds_protocraft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for protocraft."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="558e7f45f3376ca68425d5aa7fd12375bf91559821f87af5c2f87e81498915e0c6380d301ce0df54aa72ed4bb1ea0997"
    $a1="26b96a280c54b03133b7821eaa1c34b289d8cf6ae0081fb4b694d030016249f159acba3c64ffc8eb8ac10c63bbe37236"
condition:
    ($a0 and $a1)
}