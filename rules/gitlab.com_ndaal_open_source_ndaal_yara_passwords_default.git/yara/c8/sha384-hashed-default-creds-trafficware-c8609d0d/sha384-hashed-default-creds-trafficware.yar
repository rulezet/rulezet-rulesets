rule sha384_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d98035438b2214ab2b6caafd49b589917ffe1a28d835cdfcc74233671cbff458674f68be22da5981816cf01851e10dfd"
    $a1="d98035438b2214ab2b6caafd49b589917ffe1a28d835cdfcc74233671cbff458674f68be22da5981816cf01851e10dfd"
condition:
    ($a0 and $a1)
}