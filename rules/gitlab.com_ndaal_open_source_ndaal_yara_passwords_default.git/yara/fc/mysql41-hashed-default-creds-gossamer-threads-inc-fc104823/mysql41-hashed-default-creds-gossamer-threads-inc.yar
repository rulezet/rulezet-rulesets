rule mysql41_hashed_default_creds_gossamer_threads_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gossamer_threads_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*4219D1204C5D93359DBB1E19CFE3F302A6C4A8AF"
    $a3="*4219D1204C5D93359DBB1E19CFE3F302A6C4A8AF"
    $a4="*11DB58B0DD02E290377535868405F11E4CBEFF58"
    $a5="*11DB58B0DD02E290377535868405F11E4CBEFF58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}