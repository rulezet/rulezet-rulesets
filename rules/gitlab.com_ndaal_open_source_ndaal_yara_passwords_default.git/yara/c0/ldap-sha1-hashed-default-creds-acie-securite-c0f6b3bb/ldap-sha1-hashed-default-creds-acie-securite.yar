rule ldap_sha1_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}xUjtU8mUSbuDiqVP4N3oXbALIqw="
    $a2="{SHA}AP8mKXbjJVeVDDm9EGEXb7HPoC4="
    $a3="{SHA}xUjtU8mUSbuDiqVP4N3oXbALIqw="
    $a4="{SHA}qnuodLfpjP5Mtl6Sgv5y4dMdNmk="
    $a5="{SHA}xUjtU8mUSbuDiqVP4N3oXbALIqw="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}