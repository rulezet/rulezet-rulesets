rule sha3_256_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a2="74558bcfe17e7179bda0280ae817029860716d460733f9726fd632f34518b8f7"
    $a3="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
    $a4="ab3096e75a21696828f78fae2ea6de1427c28a63a6d1a25f15855bb257ce91e9"
    $a5="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}