rule sha3_224_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1c153368c77b8f057bcd8b7ebda5bb4db727bf2ba5b6f8511c36eb87"
    $a1="1c153368c77b8f057bcd8b7ebda5bb4db727bf2ba5b6f8511c36eb87"
    $a2="7c2b4a789151c004478b2a0b16d1ab7eb0ae9fbbc17bbddeac04d6b0"
    $a3="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}