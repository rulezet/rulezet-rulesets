rule sha3_384_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="49d515950d401a15a7199d58b29240ae5e3c9c2f4881ddde9d7e29f78dbcfde73a8b47e41076492a2aac3086bca52063"
    $a1="6202681913ad62945bd2b815a2d4d41ac217ed419a0f705e26133ea8a05338e9886cb21631d34d695fbbdd209dbe97fa"
    $a2="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
    $a3="023fb079bdf2d642a5d370f80fba12d4f4ba865ce4c287aab0536af45a0e2ceb5c4bca8a07353aa43e1f5d043e9b14d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}