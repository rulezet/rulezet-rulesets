rule sha3_256_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6dd7ef0fc7657da7b51d4aab5ff3850733c621ee52f6c81a92d554cc3f12cd2a"
    $a1="a01a25d4573adb2a60d5252e428f508fe5f23657d33c53a6800865b0c3cccbb9"
condition:
    ($a0 and $a1)
}