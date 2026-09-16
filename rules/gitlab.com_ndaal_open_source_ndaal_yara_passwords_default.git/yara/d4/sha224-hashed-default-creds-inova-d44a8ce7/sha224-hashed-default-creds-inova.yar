rule sha224_hashed_default_creds_inova
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="983a708e3df2c377e2b68595e74aa1f8fe699620e194f38530c032f0"
    $a1="3f27742157314e793fc9daf55c2e7db7e4980b806acbc69b27ff372f"
condition:
    ($a0 and $a1)
}