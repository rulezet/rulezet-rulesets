rule nthash_hashed_default_creds_pokertracker_software
{
    meta:
        id = "15T2xiZ63UogQHZR9Cs0wt"
        fingerprint = "df0dba6f7ea7ed7529bb8f5e1ad5bfe1d8b4c6a4554e808c4b6421b0e2158e4f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a66b7345ca02aca8429bc224f69d12d6"
    $a1="28278c7295f5487980d7238f1db3c12d"
    $a2="2457deb6001fc4ec83e78df534f272ad"
    $a3="28278c7295f5487980d7238f1db3c12d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}