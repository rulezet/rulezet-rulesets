rule ldap_sha1_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}XW3VH7j3YVjwhGKbN/lAeamN9vw="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}XW3VH7j3YVjwhGKbN/lAeamN9vw="
    $a3="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a4="{SHA}n8I3/rPbYWYqVmb+ovvNDOMnvIo="
    $a5="{SHA}UhKLBocLqYHB6JTd7yGlwARBOnk="
    $a6="{SHA}XW3VH7j3YVjwhGKbN/lAeamN9vw="
    $a7="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}