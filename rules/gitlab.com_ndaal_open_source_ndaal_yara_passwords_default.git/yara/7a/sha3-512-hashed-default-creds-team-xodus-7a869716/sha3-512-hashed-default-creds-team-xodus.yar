rule sha3_512_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="471d6087ddf83fc1dacca51213356f2ccd0bdaed27e1636c84be34a0d5879c30c07abf47fab1a13c0d255bd44e61d7ff0b9a7ea5be7cccac482882a098aa456a"
    $a1="471d6087ddf83fc1dacca51213356f2ccd0bdaed27e1636c84be34a0d5879c30c07abf47fab1a13c0d255bd44e61d7ff0b9a7ea5be7cccac482882a098aa456a"
condition:
    ($a0 and $a1)
}