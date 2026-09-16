rule ldap_sha1_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}XX6qt487GNBNfccZGA00w93EHCw="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a3="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a4="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a5="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a6="{SHA}k7YbSCSS7OJHliJQZAvFCT4YY50="
    $a7="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a8="{SHA}vz+NoD3oiQF2cnwT058JOFq6bCU="
    $a9="{SHA}Nj6yJPb/jTxRY6iAUiKsv5OaZbM="
    $a10="{SHA}XX6qt487GNBNfccZGA00w93EHCw="
    $a11="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}