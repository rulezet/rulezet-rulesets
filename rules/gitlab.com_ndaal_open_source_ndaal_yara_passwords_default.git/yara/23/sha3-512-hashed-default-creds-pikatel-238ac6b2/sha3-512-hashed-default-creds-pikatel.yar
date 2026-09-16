rule sha3_512_hashed_default_creds_pikatel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pikatel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06ffdade2c104f07520bc3d8f2822d5f48410e77ed91bd10bd0ea914d0daec7023cd96bbfe338b88467922569b7a428006fdf3b1337c438456427e4531b01edc"
    $a1="06ffdade2c104f07520bc3d8f2822d5f48410e77ed91bd10bd0ea914d0daec7023cd96bbfe338b88467922569b7a428006fdf3b1337c438456427e4531b01edc"
condition:
    ($a0 and $a1)
}