rule nthash_hashed_default_creds_trafficware
{
    meta:
        id = "3BQABCgXvKVJoy8XJmNrOp"
        fingerprint = "aaa4648d9b47a651741f916fab6a3e30caef402705f9feef79b1d280b4cbeedc"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d9f418b2c1c2f623b4720d02d556bef"
    $a1="8d9f418b2c1c2f623b4720d02d556bef"
condition:
    ($a0 and $a1)
}