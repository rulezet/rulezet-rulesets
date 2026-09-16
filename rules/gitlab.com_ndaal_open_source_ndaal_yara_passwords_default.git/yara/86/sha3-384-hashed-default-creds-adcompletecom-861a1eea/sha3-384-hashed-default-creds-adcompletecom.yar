rule sha3_384_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e492b64edc61513302f0289185580cc0328a19ab96ec876dc5592643b0ca0c2904eaa94b6dc3daaf19891862059b4c20"
    $a1="e492b64edc61513302f0289185580cc0328a19ab96ec876dc5592643b0ca0c2904eaa94b6dc3daaf19891862059b4c20"
condition:
    ($a0 and $a1)
}