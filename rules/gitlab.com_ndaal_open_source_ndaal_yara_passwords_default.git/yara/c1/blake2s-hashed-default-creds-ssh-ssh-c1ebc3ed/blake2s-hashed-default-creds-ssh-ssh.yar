rule blake2s_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="78c4a646a1e4ceaebf203b20b97935e177253fa7eee54f6b597277570fa5e492"
    $a1="78c4a646a1e4ceaebf203b20b97935e177253fa7eee54f6b597277570fa5e492"
    $a2="e92ff577401fc80870583c9f437c1b6c3c5ecbb35388f3324469171c4549aeb1"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="d65713daf4bfd4cec7b745476c42fcdb7f34045f314f4842f6e47dcc25d27ab9"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}