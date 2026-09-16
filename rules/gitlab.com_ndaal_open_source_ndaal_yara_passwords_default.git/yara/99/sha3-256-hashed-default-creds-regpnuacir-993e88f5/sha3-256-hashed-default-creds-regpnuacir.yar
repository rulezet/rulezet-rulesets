rule sha3_256_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a80f3ff71527ab559be9f18eb4205aeb85ea7896f55534a960e50a018e75322"
    $a1="ad4dda808bc8ebeb2aafe9815bdcc1f176c9a80e2f5d92fc16e444ce8da270d0"
condition:
    ($a0 and $a1)
}