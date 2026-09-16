rule blake2b_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="999da54e7b8f6c5182d5170beb2b0c0be1bd816ef9e7acd04319d1fa2ec1808c39221fa1ad57aeb6a353f061cbb2aeade6a6acd77fbc1cb010dbbcb63a41b3a0"
    $a1="40d6c4ff78e09c19b8e4fe831eae0a8c4ebe0adacf1846b6e2794b74cc91b3215fc57f3339e203e1d5598b9dbe7adad1a25a1642197c832cc737bb086dad6030"
condition:
    ($a0 and $a1)
}