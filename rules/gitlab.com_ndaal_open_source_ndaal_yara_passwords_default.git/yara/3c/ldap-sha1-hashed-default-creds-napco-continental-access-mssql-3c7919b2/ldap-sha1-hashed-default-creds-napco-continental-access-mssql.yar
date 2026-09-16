rule ldap_sha1_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a1="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a2="{SHA}5AqM1HGUJJG5tBKlF9b9gVyl9Fs="
    $a3="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a4="{SHA}PWrPWwZkyEIsbAr6ftHTn/FVyio="
    $a5="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a6="{SHA}sAluDAvkWxGhDOww5GH76TmLLOE="
    $a7="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a8="{SHA}5AqM1HGUJJG5tBKlF9b9gVyl9Fs="
    $a9="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a10="{SHA}PWrPWwZkyEIsbAr6ftHTn/FVyio="
    $a11="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}