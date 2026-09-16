rule sha3_512_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a6fca043737a884496c41aa3cde643952028376961f3e435867125356949ce0d4156eb83518e1f62ea15cccfff5b126f5e2accf23a45d4dbe5fcb5f93c44f1f"
    $a1="ab4661328aae5f4ce70daf98f71eedeea4d7f4bc5e1b4b122881471d57f40c7cb6ddc306ab2dee37ad2f290cd68b477937bd1b1661e1c56bc5dbe0d4b8b71754"
condition:
    ($a0 and $a1)
}