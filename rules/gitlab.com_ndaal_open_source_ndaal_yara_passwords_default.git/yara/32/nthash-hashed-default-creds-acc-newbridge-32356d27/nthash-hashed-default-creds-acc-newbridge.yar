rule nthash_hashed_default_creds_acc_newbridge
{
    meta:
        id = "3PYjjqykpeev4Nw8ns5MB3"
        fingerprint = "11679438ab8007d8001b5de9e5c9556a6aecdbb5e0fb49683be0b98e2d08cbd9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="198d23ce47e7ab51349d595a24e451bb"
    $a1="198d23ce47e7ab51349d595a24e451bb"
condition:
    ($a0 and $a1)
}