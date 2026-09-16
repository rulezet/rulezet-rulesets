rule ldap_sha1_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZstFamEoKVPyEqbvjuY2Os+4+3w="
    $a1="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a2="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a3="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}