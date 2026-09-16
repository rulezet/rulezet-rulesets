rule sha384_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4984cec212baf75d96ebe1fe0716b3dfb41d21dc47be7bbbe47028db323192b03561b7e213da066603996f6ed0f11a28"
    $a1="4984cec212baf75d96ebe1fe0716b3dfb41d21dc47be7bbbe47028db323192b03561b7e213da066603996f6ed0f11a28"
condition:
    ($a0 and $a1)
}