rule sha256_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7208a9649eaba97136a9f3622af20bd4db6bcc6e18e50df2aa60d126e78b2a80"
    $a1="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a2="fe88d15496bb764bb68e7c2cc2d7626594194b4a59b45b721d58dcdefcd2d5ad"
    $a3="65f2c6d4f0b55dfd3e7555b7dfe740273a1a162e3647ac9afbd8dcf3bf745146"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}