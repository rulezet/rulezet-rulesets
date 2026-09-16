rule ldap_sha1_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}nhamhbyW4XF/+iVxPD3v0UHST+8="
    $a1="{SHA}eyAtV/IUrwFv4pI75AEQdA3Vu5E="
    $a2="{SHA}/HAy+4p5TJ8aaJB82MHXT6fl3Dg="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a7="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a8="{SHA}poGxpSm5f6S0vSIU+5qKxrIpf+c="
    $a9="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a10="{SHA}J+Pm6jkjB/hq+dChQEsVrifXBw4="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a12="{SHA}p7fQdLrVZIO7ycjITYE38gb8rio="
    $a13="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}