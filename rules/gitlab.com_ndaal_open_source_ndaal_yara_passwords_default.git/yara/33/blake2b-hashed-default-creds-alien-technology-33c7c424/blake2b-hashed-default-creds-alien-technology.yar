rule blake2b_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
    $a1="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
    $a2="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}