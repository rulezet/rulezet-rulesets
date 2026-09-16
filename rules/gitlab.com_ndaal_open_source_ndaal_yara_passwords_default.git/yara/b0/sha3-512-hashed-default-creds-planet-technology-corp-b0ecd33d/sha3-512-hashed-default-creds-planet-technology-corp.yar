rule sha3_512_hashed_default_creds_planet_technology_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for planet_technology_corp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afd5a52299dd6541554feb3bfc5f8dbacfaadfbd593cd9b2b68c9b9b65fa6447a0e310e66d8c5aa7faa4eb3700e3c7678ee245a1c35c0f59cbd21b5f07d490a9"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="2aa80e54a2db37c15135f67aaadd00e2f277b776876505b96f419ec28c13310e3b4c6cd513207e82e039d7eac9e5d44ec761c449c2cc519e6d9ee2de62b6840a"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}