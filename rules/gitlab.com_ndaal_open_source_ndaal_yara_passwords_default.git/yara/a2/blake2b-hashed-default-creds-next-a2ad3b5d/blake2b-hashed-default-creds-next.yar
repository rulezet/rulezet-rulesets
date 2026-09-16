rule blake2b_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e38c657b4febf840cd67451c2a18c40360581064289f2fc07be57b523ecf84fda49ed03d9a9f0d58c6b8b99634fab7ce9a95748a36747351099c2a47066a3f3e"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
    $a3="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}