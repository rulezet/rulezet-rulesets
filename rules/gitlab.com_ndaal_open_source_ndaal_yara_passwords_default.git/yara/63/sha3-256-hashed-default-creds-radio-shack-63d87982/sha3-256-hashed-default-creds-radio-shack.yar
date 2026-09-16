rule sha3_256_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3efad2b03b031d2d7c8bb3b19f66eb66dfec0d70a09a8ead2f3a66bf77eac333"
    $a1="faef749b7f8d82a0c144e8f53fd815fc179f1cc40870f831046da2c89e2fc010"
condition:
    ($a0 and $a1)
}