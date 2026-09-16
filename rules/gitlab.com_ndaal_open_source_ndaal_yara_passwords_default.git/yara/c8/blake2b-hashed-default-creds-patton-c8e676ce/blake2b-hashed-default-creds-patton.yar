rule blake2b_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a1="cff65eee57a527abb187e2c515b4416861d8cd83c413a6d31e09f4d8ec305aa4e3d3eafbc9df47ce184c26468930951fbf6fc2e53ae1a1352feb6d58d889c68f"
    $a2="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
    $a3="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}