rule blake2b_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8035e91023a1762a7449c9f82a6d78c3bbb66d45f8635e5d8f58b56f982a6c12e039ff09c59831867c70e4504a1a8b09a6179140ffda45b7319f246b1f1dd9f0"
    $a1="572d1805d672afb62249e016f90c350e3a9f834b65b1a8b2b40aa3c9e5d059e6224408d7c9114294e0e65ac0a707aad48eee61242fb14f820f22ca207e9861bd"
condition:
    ($a0 and $a1)
}