rule sha3_224_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c58aaeb2dd12ac365f66c9d43cdd1d1cbaa9ed1166c8777b3973d8c"
    $a1="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a2="9976702f28a05a97104c42c54485cc5ba9934c2678cfb760019f2b3b"
    $a3="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}