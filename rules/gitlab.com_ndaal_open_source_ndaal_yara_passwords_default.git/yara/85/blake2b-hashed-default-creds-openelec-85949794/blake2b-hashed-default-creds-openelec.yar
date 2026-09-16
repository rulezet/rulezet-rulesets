rule blake2b_hashed_default_creds_openelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openelec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aced3c4754f990dc167276adebd5c870ba464e602b091bc3d1d3ee90a5ef87143c60db283bef5ed42f85ebc727cc9adfc9191da9a7895be3dbe8440342f7345b"
    $a1="1febddcf161e79399c32859dc9664bbc20423f2f11ff1e95884e112a253fa65b2dafdd15918512a58686a0bd7bb84b4afb9322f6945130fd6959c2091fa27b9f"
condition:
    ($a0 and $a1)
}