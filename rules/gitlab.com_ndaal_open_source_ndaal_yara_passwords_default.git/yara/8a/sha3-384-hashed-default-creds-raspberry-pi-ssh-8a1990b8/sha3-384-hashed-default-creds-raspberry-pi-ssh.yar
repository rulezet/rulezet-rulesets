rule sha3_384_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38bd5c110d1b0c706ee925264a49639dd650e185292e02fa3820a98d50e14c81359ab7d9084cd041bb82a341694bea71"
    $a1="65ddd20a75473b10f2f7d285b625a6beeb0064eb07c915e6548468c5d4b5a320a7ec34a1be509b63236eca3ecd635301"
condition:
    ($a0 and $a1)
}