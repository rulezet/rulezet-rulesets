rule sha3_224_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d780e66f046d5a8c6e908838c3569d9938c0a1edd89a1fdc092e566"
    $a1="8d780e66f046d5a8c6e908838c3569d9938c0a1edd89a1fdc092e566"
condition:
    ($a0 and $a1)
}