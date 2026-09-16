rule ldap_sha1_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}08T4O89TQV5EaUEGtbAP9iot6mI="
    $a1="{SHA}08T4O89TQV5EaUEGtbAP9iot6mI="
    $a2="{SHA}j9RTcM3RjqKXKYcW1s/7BI7mYrQ="
    $a3="{SHA}oYcuMz0OUmRPYSXaInZTD36+Xnc="
    $a4="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a5="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a6="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
    $a7="{SHA}yFgkdXo3PJjRe1a06ppWScW8tV8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}