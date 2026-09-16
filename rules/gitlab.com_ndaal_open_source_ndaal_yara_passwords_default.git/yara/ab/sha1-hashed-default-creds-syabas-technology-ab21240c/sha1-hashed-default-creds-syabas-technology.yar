rule sha1_hashed_default_creds_syabas_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for syabas_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="c6f1e1be122769209226484ec780ac4159225562"
    $a2="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a3="250bb7d26863f440fa6cdcce93a5cda14cc719fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}