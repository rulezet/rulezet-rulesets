rule sha384_hashed_default_creds_ssa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssa."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
    $a1="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
condition:
    ($a0 and $a1)
}