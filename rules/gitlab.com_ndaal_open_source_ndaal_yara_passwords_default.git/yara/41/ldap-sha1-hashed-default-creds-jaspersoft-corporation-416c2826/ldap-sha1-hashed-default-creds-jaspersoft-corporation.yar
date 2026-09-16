rule ldap_sha1_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a1="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a2="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a3="{SHA}SJmoSfajzueeKtW33ZPQp/J21JM="
    $a4="{SHA}utownlHm6mCh3SD8O5FzoZftBvU="
    $a5="{SHA}utownlHm6mCh3SD8O5FzoZftBvU="
    $a6="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
    $a7="{SHA}jme7JrNY4u0g/lUu1vuDLzl6UH0="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}