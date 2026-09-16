rule sha3_256_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a7c122f023a9592064eeaf29aaef9386bc49cabf221eaeeab657fda12260b125"
    $a1="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a2="035ea5e12cb4a59f4923d04f5782cd9b5404856c22cec75f1e98099e47c4a8fb"
    $a3="4660630aa2718174e349ac368b7667d0568ba8286106dfec7edcdff7f2769a15"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}