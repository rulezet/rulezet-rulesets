rule sha256_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a1="8fb6d5f37e8055ce720bd0b1d56587f88c0071f285966ba17e72b2b12672aa73"
    $a2="5912d5590ceedd61724ee20d37b515427916c915081bccad29e0c684476014c4"
    $a3="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
    $a4="c797f6834c354fedaee9e19bd52583f73ee2255bea1d6cc412168eff78675c99"
    $a5="9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}