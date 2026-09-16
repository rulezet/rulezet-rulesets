rule nthash_hashed_default_creds_ftp_ftp
{
    meta:
        id = "2jiVEQC08FD2gOfvWZaMMR"
        fingerprint = "fe4033169d6082f4fd63c63292b9ebfe9c2dde8f4593946f0ccd0aeaa64faae2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9865c4bdcd9578a380297c5095e6c852"
    $a1="9865c4bdcd9578a380297c5095e6c852"
    $a2="823893adfad2cda6e1a414f3ebdf58f7"
    $a3="823893adfad2cda6e1a414f3ebdf58f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}