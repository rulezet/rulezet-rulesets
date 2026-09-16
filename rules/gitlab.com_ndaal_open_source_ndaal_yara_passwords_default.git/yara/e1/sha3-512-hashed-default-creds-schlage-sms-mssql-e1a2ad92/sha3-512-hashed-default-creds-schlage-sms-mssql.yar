rule sha3_512_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
    $a1="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a2="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
    $a3="6ff1755e0fecc408e984ac26c8776c950bb31a429eeda7ccff39770b77314d9aacd339854ca8a3dabc4b087e95f6b216421523e070bb0d02c77792f73a35ec3b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}