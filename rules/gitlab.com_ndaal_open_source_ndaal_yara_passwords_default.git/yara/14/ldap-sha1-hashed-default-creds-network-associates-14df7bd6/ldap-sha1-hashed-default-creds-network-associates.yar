rule ldap_sha1_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}jzI34Up76x4/WYhmovKVnH4Rcp8="
    $a1="{SHA}1WaK9IfAGrg1FckOs5Uqf5Z3688="
    $a2="{SHA}VTs1+OVyrKmmU41dbpl66xQRyxo="
    $a3="{SHA}ghdR2KtMbXXZJ+fwktVb6Jb39no="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}