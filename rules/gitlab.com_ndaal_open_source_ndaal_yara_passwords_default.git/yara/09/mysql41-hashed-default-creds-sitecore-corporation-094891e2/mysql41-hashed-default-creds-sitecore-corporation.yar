rule mysql41_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F33AE6DD04EF4C7C1D3105568E7FB7C1EE16C937"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*667F407DE7C6AD07358FA38DAED7828A72014B4E"
    $a3="*6B13000B387F39BA08C0B7A6905817C89A256964"
    $a4="*F33AE6DD04EF4C7C1D3105568E7FB7C1EE16C937"
    $a5="*EFE6560E62AD6038EF1BFDC54F39B01EBF1C4B09"
    $a6="*84869AED8A7235127BFD0AD4A55E335B29ADE3AD"
    $a7="*A454318A898D03E5CC2468D9E6BB4EAD57F7AB0E"
    $a8="*894549142A2819BC7952B608F00C489C989212E8"
    $a9="*A8EC13FA8353AA1BEF06EDBF73EBB1029A343DCE"
    $a10="*E8BEE713F0CBBB9F9B09623007E2826138710274"
    $a11="*F43F70881102C664D9A31DE3EDF32F8CDF7F4540"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}