rule sha256_hashed_default_creds_schneider_premiumftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumftp."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ab18fd7a14d6d731de6eb91fb5bdb2123e705af7fe2442139198f06b7948feb"
    $a1="23a1d40404715c2a6970c6350b01920ec417bdb3f1f6f399ecb3f073542b58eb"
condition:
    ($a0 and $a1)
}