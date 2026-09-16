rule sha3_256_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="2032a7663effc6b47d3d2476625c0f085d89cdb9d1df44904fe558b65a703cb8"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="4bfa7f98a288d7aa4bbf5f3b54a2d4c4cd04f0375823b61a7f48f60f2f88f46e"
    $a5="7df6837cb53e0cd82f2523ba2ac7b79767b35a0b4534773fffed89a8e97132a4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}