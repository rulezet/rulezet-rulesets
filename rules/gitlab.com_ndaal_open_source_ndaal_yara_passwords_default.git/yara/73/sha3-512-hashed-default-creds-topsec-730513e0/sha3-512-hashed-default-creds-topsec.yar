rule sha3_512_hashed_default_creds_topsec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topsec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e63615d49da92d21fe3cbcd3289b694f7f90cd4c4460d6f0ef407fa8fd83dab803096a1c1111ccd1f0bc2c0795f15e1685199926285341a30b1035b8454a5584"
    $a1="dc8734ec38acad7854cfac66c0a1e2c342ade4a2a0ebbb790cea8e0a09753142f3b3d490e4f80276710a790a4b451cfcc02fc35f11c75b00ec03a13f55d6f407"
condition:
    ($a0 and $a1)
}