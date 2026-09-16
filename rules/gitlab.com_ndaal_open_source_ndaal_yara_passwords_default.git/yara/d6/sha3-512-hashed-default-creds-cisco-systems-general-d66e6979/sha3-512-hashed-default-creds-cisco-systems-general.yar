rule sha3_512_hashed_default_creds_cisco_systems_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_systems_general."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a1="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
condition:
    ($a0 and $a1)
}