rule sha384_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75e04979409f1a890cd878cc917327a7bd482d7a31db27c8e7dce0d405acd04420427daa6fbc5a5df78eb7ccda04a62b"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="4d361ba1f1b7d16b6c92cb212b54754b8bfaefd426790738d42c58dc1e8ac24a9ec915444e5e2bbdd379bcb348d1e0e3"
    $a3="3d9fe3fac33df0a8060204598edf4b25dcdaf8c28581bd7a11b5220ce26b44686ff58c02318385fb1e2842ad113e13aa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}