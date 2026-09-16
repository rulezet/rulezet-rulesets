rule ldap_sha1_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Ktt4mj5exTVTJpH3plzY6Vc5TzA="
    $a1="{SHA}Ktt4mj5exTVTJpH3plzY6Vc5TzA="
    $a2="{SHA}/AsgweyOFJc8H0yTWFML1tJXd6M="
    $a3="{SHA}/AsgweyOFJc8H0yTWFML1tJXd6M="
    $a4="{SHA}xyh3xRp3sqr8B3HYIaJipcamGGo="
    $a5="{SHA}tMVNviw06cHL8n3nmjZhcXsf6lI="
    $a6="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a7="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}