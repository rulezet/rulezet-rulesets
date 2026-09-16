rule sha3_256_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="71bc7d7523b4b6677a662b404a0d9645dd022942c1f43122beced8650fd8b86c"
    $a1="71bc7d7523b4b6677a662b404a0d9645dd022942c1f43122beced8650fd8b86c"
    $a2="1df8dc39904e7c2cc6cfaf6238503488557be3319aa790948ca068cf0946b2df"
    $a3="1df8dc39904e7c2cc6cfaf6238503488557be3319aa790948ca068cf0946b2df"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}