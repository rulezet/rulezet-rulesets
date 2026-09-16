rule sha512_hashed_default_creds_ca_process_automation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_process_automation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d822c18a499b2734d43f6af8173cb9045e294b2b822d6e1ba10672684b20bf1cf47944c9039021ad7315d10d3dc0aaddff0ed456c0f610c75b1c2f19aabb76c1"
    $a1="d822c18a499b2734d43f6af8173cb9045e294b2b822d6e1ba10672684b20bf1cf47944c9039021ad7315d10d3dc0aaddff0ed456c0f610c75b1c2f19aabb76c1"
condition:
    ($a0 and $a1)
}