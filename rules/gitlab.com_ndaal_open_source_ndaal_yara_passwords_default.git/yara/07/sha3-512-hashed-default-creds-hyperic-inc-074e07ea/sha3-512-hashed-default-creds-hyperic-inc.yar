rule sha3_512_hashed_default_creds_hyperic_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hyperic_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="937be475e5fac0db8642ee99e1b2a73943e0ac8a19ed452ac58e0e19d4e87a926eef0d9d4a2ec56d7565e8e4d28a045f4fa4d1064f1686ca0babd60e0f5428f0"
    $a1="937be475e5fac0db8642ee99e1b2a73943e0ac8a19ed452ac58e0e19d4e87a926eef0d9d4a2ec56d7565e8e4d28a045f4fa4d1064f1686ca0babd60e0f5428f0"
condition:
    ($a0 and $a1)
}