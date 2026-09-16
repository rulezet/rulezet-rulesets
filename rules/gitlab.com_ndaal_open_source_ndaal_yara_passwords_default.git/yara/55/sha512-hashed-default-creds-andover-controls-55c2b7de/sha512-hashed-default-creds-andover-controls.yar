rule sha512_hashed_default_creds_andover_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for andover_controls."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="653c12e21fbda7116eb0373d0c185c3cd1873bdeddac6813f84d3e6d7b9370f825a35ec97d99925e4525828570e0a62a94e639109e8a23b55f397565bb068878"
    $a1="653c12e21fbda7116eb0373d0c185c3cd1873bdeddac6813f84d3e6d7b9370f825a35ec97d99925e4525828570e0a62a94e639109e8a23b55f397565bb068878"
condition:
    ($a0 and $a1)
}