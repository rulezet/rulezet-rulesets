rule nthash_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        id = "2ZeEoG85ifv6IiA2Ti75HI"
        fingerprint = "3977969064f28fa7e338c31dc83aa2cf48c2802d3ffbd38555523d2bf6c438d7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6e43519245849c2b4a925f4a90c8941"
    $a1="b6e43519245849c2b4a925f4a90c8941"
condition:
    ($a0 and $a1)
}