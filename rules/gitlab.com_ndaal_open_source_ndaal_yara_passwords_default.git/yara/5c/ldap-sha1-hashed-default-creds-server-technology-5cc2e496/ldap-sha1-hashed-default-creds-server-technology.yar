rule ldap_sha1_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}saE78Pc9hJVcKOjB01rhhwHdkdg="
    $a1="{SHA}eAznGxAWCyP1p85OKglNnAbjM5g="
    $a2="{SHA}OIt/H5OM+gfBIpb4MrHmzKbavYE="
    $a3="{SHA}VWeSNPH2ZaqI/wLtI4gzsJa5lpM="
    $a4="{SHA}Vqryqp6y+v/rVGefUwWAscSq/lw="
    $a5="{SHA}CdyrefU9pXk95zuuCcyzJcmO3tU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}