rule nthash_hashed_default_creds_pips_technology
{
    meta:
        id = "xiOToRyft7MZy7bm5LuQN"
        fingerprint = "61ee3c41d631dbd9f2d73601742eb55843130bb1991ff01fca4edab6a85d3993"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7929aba6ecc04862b491bb16553bb43a"
    $a1="7929aba6ecc04862b491bb16553bb43a"
    $a2="99e03982a9c5864058e3c5ed439fd5dd"
    $a3="99e03982a9c5864058e3c5ed439fd5dd"
    $a4="1bfcc4fd0083b569ad0aad3692eb3f38"
    $a5="1bfcc4fd0083b569ad0aad3692eb3f38"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}