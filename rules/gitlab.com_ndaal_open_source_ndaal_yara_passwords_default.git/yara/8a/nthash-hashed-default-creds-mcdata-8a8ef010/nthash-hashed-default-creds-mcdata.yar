rule nthash_hashed_default_creds_mcdata
{
    meta:
        id = "1kL92N8FffNv0tdAEAnhjf"
        fingerprint = "5b9d8b5982fa16497329eee59d4a53bffd5f7465338e009824362bdb0f6d2fa0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="d144986c6122b1b1654ba39932465528"
    $a2="c3b7d8073fad0656a91a83a895b79ffd"
    $a3="4f05175152e178e3fe0243f4108ab7af"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}