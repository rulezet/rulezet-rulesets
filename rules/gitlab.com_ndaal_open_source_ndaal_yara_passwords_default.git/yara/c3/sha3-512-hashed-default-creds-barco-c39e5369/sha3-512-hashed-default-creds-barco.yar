rule sha3_512_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6bcf20448e4cdb64bb38c660819f9996fcf687be9533659412767367d6f8ca628774597eab95ed7eee8835de99f3c056174d67b393892adae8e936a8defb2d5"
    $a1="36f95e0cffeff5c84398e9587112976d67baa79cd791103a0c921a898dde614ee74c04bc2b4a80e80cf164481b54f471d440b4b094ea61279a08c9d1f50cf7a1"
condition:
    ($a0 and $a1)
}