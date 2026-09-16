rule nthash_hashed_default_creds_galacticomm
{
    meta:
        id = "1ATeEG46TwjgfpO7Rlf7TM"
        fingerprint = "580e73b41c867de1f372afbbf3018d2251e0fc4574fdc288a095239eede711ea"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="033b10dd9c197b02ec45d7045a966fba"
    $a1="033b10dd9c197b02ec45d7045a966fba"
condition:
    ($a0 and $a1)
}