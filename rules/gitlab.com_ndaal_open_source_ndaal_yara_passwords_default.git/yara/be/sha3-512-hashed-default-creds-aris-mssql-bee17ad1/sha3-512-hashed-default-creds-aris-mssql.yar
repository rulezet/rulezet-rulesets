rule sha3_512_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="794ba3c101b035c39d559a0f2fcc9bdf84cbc9e7572e9c133bdea12417186c0f433a0404763b1c01fc8c3cd8de4452049de50e00b35b009fb259d2d1cb70f0a7"
    $a1="da51ef2b1b97b232805d160076014f9713007a95d5399b4fe765e158c6bf394f7f5786c708770b6062009bb99e8deffb294a668a1135a2f80a9aa66bc47f9b53"
condition:
    ($a0 and $a1)
}