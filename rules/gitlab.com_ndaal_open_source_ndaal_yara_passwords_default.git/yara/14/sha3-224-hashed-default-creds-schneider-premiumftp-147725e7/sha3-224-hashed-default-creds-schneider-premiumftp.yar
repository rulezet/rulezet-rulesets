rule sha3_224_hashed_default_creds_schneider_premiumftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumftp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eca1b37497244881579be9058e9b7211159de6f1df36b55d22cef8d3"
    $a1="a4d6b17f5d20ce6223a308d938b07a9f3ec093233757eb9e387c963a"
condition:
    ($a0 and $a1)
}