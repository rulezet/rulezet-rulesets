rule nthash_hashed_default_creds_dell
{
    meta:
        id = "7gGeeT0WzErHOa1P2TzhB5"
        fingerprint = "d6597ce66b45018917e351b4ff0f22e16deec3ca9fceb4ddcd64bc54b068930f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c7881d6a4603ae3bc7dba0fa8b6a3b7"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="c7d5c6839e28027de55b9f244f672efc"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="209c6174da490caeb422f3fa5a7ae634"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="3ff801ba973804df4c21a4866fe7b014"
    $a9="d144986c6122b1b1654ba39932465528"
    $a10="d9d247a789f19a41659c6611240e10e0"
    $a11="e7d21aa3a0517f3395583852f8b6556e"
    $a12="030b0c393eb8a601c800cea0054fe334"
    $a13="329153f560eb329c0e1deea55e88a1e9"
    $a14="d718adbe2a6fc8242442da6dfcf4f7a0"
    $a15="710c980e55faa60837d875fba41ed45e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}