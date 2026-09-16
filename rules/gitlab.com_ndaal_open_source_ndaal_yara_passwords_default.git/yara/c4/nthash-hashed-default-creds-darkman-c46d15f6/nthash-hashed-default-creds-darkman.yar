rule nthash_hashed_default_creds_darkman
{
    meta:
        id = "6rtDgOaISjcJCTQARCYu5L"
        fingerprint = "c8b0c8aee335158aa32c692846c564a0c754e2168df75aeb84ad186a5b508fe2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2d184e1506c508a8f48564cc442aac80"
    $a1="2d184e1506c508a8f48564cc442aac80"
condition:
    ($a0 and $a1)
}