rule blake2b_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed6a925021ee9b8e62df1ebb9bc5f761e3c1f5770b7b4664fda403ef20ca6dcd3a04631affb86531551bdd8abe1ec3a5bffe645b43e3d55e43bf5e9a37aed994"
    $a1="57d19df1bf7aa1be24b7cdef2042043b5f9fa65f742caf1aa604f82625dd91f6a657b2ff453f91cf7ec071394c6afc582c0ebd26f8a4215e7ffad83fe7703002"
condition:
    ($a0 and $a1)
}