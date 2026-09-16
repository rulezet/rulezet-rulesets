rule blake2s_hashed_default_creds_jde
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jde."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e2620913f0fa7212d691f91d133988e9163b9887ec78155454a781d006f4055"
    $a1="5e2620913f0fa7212d691f91d133988e9163b9887ec78155454a781d006f4055"
condition:
    ($a0 and $a1)
}