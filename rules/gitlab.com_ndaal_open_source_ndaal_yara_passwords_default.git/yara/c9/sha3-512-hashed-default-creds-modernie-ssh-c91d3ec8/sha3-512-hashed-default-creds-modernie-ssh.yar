rule sha3_512_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba7e0993284435f7e8b3220617d8cbb4751909686649a9f793d15334081cf76be4b3ee96743ee9cc499022d412f4b22d486db65ee0d12df800cd299840f86fae"
    $a1="2869c26f456718306d1175e76906d7d79830e1342b7b73f1f56ae8cdd6950160e1320ff50058a7e1db030a868dd9f593aa37b99149461dc93181d25130fa3c45"
condition:
    ($a0 and $a1)
}