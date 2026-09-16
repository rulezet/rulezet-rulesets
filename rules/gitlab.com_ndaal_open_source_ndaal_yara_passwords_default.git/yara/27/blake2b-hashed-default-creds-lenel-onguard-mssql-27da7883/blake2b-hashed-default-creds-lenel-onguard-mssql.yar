rule blake2b_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94bfc4b4c3b1fbc1c07701221d0fd293a111ab28970fb5609b093a245dbbf90b36f39153283230fcf08b8f9342378fb7784fd94cdfa85abc81812d32a7898c03"
    $a1="600b2d139f6205822171838b01a909fa123d65719ed0748695f9129578d62798dd4977435a3435af18b9abaa2b201347a259659093c02bad254a7ceecd51877d"
condition:
    ($a0 and $a1)
}