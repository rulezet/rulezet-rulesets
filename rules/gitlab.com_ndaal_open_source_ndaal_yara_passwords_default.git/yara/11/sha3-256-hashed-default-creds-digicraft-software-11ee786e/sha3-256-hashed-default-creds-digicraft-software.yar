rule sha3_256_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="017f703e717fa5c2313cb2cefd06faf8afb31a0a79f75ab3959b354aafd8732a"
    $a1="f7266b98396e2bfe8e44de46d72bb3d3b86ee3d5e6fb7fff9d89f980ac664598"
condition:
    ($a0 and $a1)
}