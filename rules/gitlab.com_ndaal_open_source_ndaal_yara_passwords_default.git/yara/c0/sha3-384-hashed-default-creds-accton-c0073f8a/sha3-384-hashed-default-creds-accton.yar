rule sha3_384_hashed_default_creds_accton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accton."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a1="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a2="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
    $a3="36523b3db866bb3caa9537c371b13b74da80a39bcb574ed825912b16f939384d20552c8f34f60719a2c708b168fa4a74"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}