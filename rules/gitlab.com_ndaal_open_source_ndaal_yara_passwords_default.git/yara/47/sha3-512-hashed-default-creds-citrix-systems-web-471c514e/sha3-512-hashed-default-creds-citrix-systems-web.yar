rule sha3_512_hashed_default_creds_citrix_systems_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a1="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a2="5c28fa545a9f51d21f4ef7278184dc7e7809a64d9e9a19c98a6498480c38ea499828aa6553a6d8bf6c4dd82c9a72a19f45cc83b164860585c7facd622510561f"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}