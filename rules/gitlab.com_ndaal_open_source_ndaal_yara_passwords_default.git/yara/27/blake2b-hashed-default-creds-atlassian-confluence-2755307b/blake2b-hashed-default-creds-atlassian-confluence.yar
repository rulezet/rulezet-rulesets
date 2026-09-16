rule blake2b_hashed_default_creds_atlassian_confluence
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian_confluence."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcdd4a4c532ba2a14f621165c4ec6b437f5d51dc28f02e0567f865742380997fa06fc2911bb98015823b32c7f1690ae93160456998fae1cc7cbdb79561666d9"
    $a1="9efac5c127bb23057244088ddbff04a33d4f0f7c9e5a441df1a2dbb6a5c969db43717d48f64bcad47e6bede8cee3ccaac639e5afd5db1d7a268f6e82fe4c4dd6"
condition:
    ($a0 and $a1)
}