rule sha224_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea296f64710b090f1016dbac77b820f57c6ee755a7a71f46bbb4b32f"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="ea296f64710b090f1016dbac77b820f57c6ee755a7a71f46bbb4b32f"
    $a3="3e779dd776252527f0f7178bf00b49151ac85b6559bcdac4eb5eb514"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}