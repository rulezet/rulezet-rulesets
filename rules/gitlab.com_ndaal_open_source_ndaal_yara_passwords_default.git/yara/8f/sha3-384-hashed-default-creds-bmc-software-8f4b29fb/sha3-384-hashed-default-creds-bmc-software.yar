rule sha3_384_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be15acb7f4f0a146e35635403b0a0343f84aa3a914921e5e063dc348555f7b4c28cc6cb77138d4fc91658b049d0ad3a6"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="a969b7ebb7d36c724aea58110580053fdff1169bad7bbeca009bf014ced6f73665d92c85cff519dfcf106c887b1e4948"
    $a3="66569c23c6673c6680f54058fe977f85aa13db77beeba4908aa343467ef0a1e18377f17a137b692fc625d503f8347754"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}