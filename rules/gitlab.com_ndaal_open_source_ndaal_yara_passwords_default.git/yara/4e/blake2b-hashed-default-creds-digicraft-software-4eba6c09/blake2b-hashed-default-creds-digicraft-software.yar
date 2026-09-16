rule blake2b_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f82be8f37360380ea46cb18b230adf21dda1c5213bffd904f89dd09d4d8d7b0b8b2b29b7263ccb54c71e5f0b74c94b16cb01b273754a63ee136f1608bda7896"
    $a1="6e93a4726000feeafd62bac1d9ffdbff801dbb19105f93928165b0bb686dbe4f9dc857920cc0a9c80cf98992ad485c5fa5ec2e0190356c10f689b0cc547249be"
condition:
    ($a0 and $a1)
}