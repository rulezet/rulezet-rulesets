rule sha3_512_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="763b7c9572ba528fb4626d620da16eef5a531293bf436aada2b6499d19d4ebbb31f156ac7ecb739664d4b53dc9888a98ee0285741280a9db9d411a686773d170"
    $a1="6a44eada586fd0787145c2f11b77da92630761612222524a2618dcfc10ea80f163ae71add99eea26db0d06b3123641263fd9dc95f146fae71afbe8615db31657"
condition:
    ($a0 and $a1)
}