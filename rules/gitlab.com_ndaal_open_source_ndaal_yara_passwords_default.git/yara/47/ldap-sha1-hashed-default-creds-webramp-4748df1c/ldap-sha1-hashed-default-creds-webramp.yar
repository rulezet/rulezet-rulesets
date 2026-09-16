rule ldap_sha1_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}6f+ZWktf79gCgu/9H2tS090gqfY="
    $a1="{SHA}lAeH7MoeRxAFl3Smu9zQj7ZrECk="
    $a2="{SHA}N1ixSIzQPVTptux/M3yFY1821M0="
    $a3="{SHA}lAeH7MoeRxAFl3Smu9zQj7ZrECk="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}