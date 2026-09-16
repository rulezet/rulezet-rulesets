rule mysql323_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b44775d226429b1"
    $a1="7b44775d226429b1"
    $a2="4a2a2992420660a7"
    $a3="7b44775d226429b1"
    $a4="649e8432104b4a47"
    $a5="7b44775d226429b1"
    $a6="7b44775d226429b1"
    $a7="077ff75a4925858c"
    $a8="4a2a2992420660a7"
    $a9="077ff75a4925858c"
    $a10="649e8432104b4a47"
    $a11="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}