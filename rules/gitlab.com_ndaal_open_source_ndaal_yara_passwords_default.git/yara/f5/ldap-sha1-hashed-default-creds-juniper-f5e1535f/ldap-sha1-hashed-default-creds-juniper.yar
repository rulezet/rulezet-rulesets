rule ldap_sha1_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a1="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a2="{SHA}5c+2irAGdhhlWwDGjYczY/4StyM="
    $a3="{SHA}5c+2irAGdhhlWwDGjYczY/4StyM="
    $a4="{SHA}Y2fEjdGT1W6nsLqtJbGUVeUp9e4="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}glee/aW9bOYEewkD/6Ri8sHh2mU="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}osUMjHQzDFtU6gth5vv+6iB/Y5o="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a10="{SHA}JYeMvDhGQcHVz1L/iTWElbs05lw="
    $a11="{SHA}JYeMvDhGQcHVz1L/iTWElbs05lw="
    $a12="{SHA}1sU4nyLeXbsz33I6Mwm0JzqdLOc="
    $a13="{SHA}hFG6ihTXl1PTTLM7UbpGtLAl64E="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}