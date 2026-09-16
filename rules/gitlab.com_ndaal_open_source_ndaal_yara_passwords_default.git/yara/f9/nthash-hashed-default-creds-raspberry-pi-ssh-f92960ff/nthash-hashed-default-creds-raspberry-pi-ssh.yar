rule nthash_hashed_default_creds_raspberry_pi_ssh
{
    meta:
        id = "5THcwDi4SUbZw7yxyGF7FC"
        fingerprint = "d7cce12dc82bab8fb46511efc54f4cc1989dec04a0f0cbf3e34bd234c5347a58"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cecadc1061009aedacc80a2de584a5f5"
    $a1="b3d4399ab6c7d4243634060b8f924187"
condition:
    ($a0 and $a1)
}