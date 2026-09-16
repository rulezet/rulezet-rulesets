rule blake2s_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
    $a1="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
    $a2="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
    $a3="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}