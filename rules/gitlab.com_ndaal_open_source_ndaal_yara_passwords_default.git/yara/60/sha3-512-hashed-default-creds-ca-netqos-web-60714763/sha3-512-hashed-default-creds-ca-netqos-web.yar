rule sha3_512_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b8efb1164e3b09c35749e60e804fe5d1b1193ac6f9e7c9c0cfb8a09f235b470e7ec5a0e60279fdf44bbf3dd5c0c9c2a73df77dbcfce26c0a8bc746bf8df5b63"
    $a1="7afd2de3c9e03f3254b9cbc545ee7594bf9ce416b52373d04eb1f51c573005052afe244517d11a2b7c1387ce78d333516bbec41bedad3c43062ef42b0008e43d"
    $a2="7b8efb1164e3b09c35749e60e804fe5d1b1193ac6f9e7c9c0cfb8a09f235b470e7ec5a0e60279fdf44bbf3dd5c0c9c2a73df77dbcfce26c0a8bc746bf8df5b63"
    $a3="5b9d6056946ae91d3e55a61a3604a1aa7d0e8ade4153ba30065da10c870298473996a6df39edd1bc81c5c7dabab0196aa3570421b57eb193101d7e53f2319f04"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}