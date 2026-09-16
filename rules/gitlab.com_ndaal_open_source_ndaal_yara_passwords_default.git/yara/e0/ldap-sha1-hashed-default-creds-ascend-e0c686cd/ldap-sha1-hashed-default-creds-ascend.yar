rule ldap_sha1_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}AT3jRWbUHNxUR/IoIDvbrMxh+gc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}uPrYkdQxTdwx04LOaki9Pj/xNbc="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}thGulhlNPC3nriYN5RSbkGwbp2I="
    $a5="{SHA}midxgpchjDdXw2XTV9E/SdD6MGU="
    $a6="{SHA}qd01G+4mFQrM/M03Acew2yY3mJY="
    $a7="{SHA}rM+IHoIe1iyoQtNBZEJqfZIVqUg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}