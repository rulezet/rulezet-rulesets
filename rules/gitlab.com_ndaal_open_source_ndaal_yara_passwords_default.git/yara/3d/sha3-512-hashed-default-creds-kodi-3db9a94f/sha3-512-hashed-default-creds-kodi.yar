rule sha3_512_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8377fee0fe489ba99075f2691d5d59f84ab22471f5cce8345888bb1f56faefb230c8f25abbe880007f249925d3ee5e471dd5e559747ceac4aabd9cef62a3f493"
    $a1="8377fee0fe489ba99075f2691d5d59f84ab22471f5cce8345888bb1f56faefb230c8f25abbe880007f249925d3ee5e471dd5e559747ceac4aabd9cef62a3f493"
condition:
    ($a0 and $a1)
}