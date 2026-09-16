rule blake2b_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="418452092fc0abac2681f8ef7d5a24aa48f54516fd6196097ba2a09bca5acf0548ee922a92ceae05c635adfbbfd7eeb354d8f46a8550af0194ae9ff9dfc6d401"
    $a1="418452092fc0abac2681f8ef7d5a24aa48f54516fd6196097ba2a09bca5acf0548ee922a92ceae05c635adfbbfd7eeb354d8f46a8550af0194ae9ff9dfc6d401"
condition:
    ($a0 and $a1)
}