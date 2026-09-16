rule sha3_384_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4ecc5cbbefcac3adce0f0559989cf2a8a67c0151b7474ac5ee97bfbdc163437c9daf6eefa3da260100506b3ff6d81e8"
    $a1="39ffb7daeaa5c4497a5a8b9d2431e22e804519dc55e9ac48c52d5d469f6498b4f75b402518630856d0237136e39b3dfb"
condition:
    ($a0 and $a1)
}