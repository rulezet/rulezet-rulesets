rule ldap_sha1_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a1="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a2="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}CY0sjqT3aTdu99rJcwIU39OIvAU="
    $a5="{SHA}7+PF5HxZWipHtgXTUTQDG2FI2Eg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}