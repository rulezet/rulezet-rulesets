rule blake2b_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="628f4adc600a551eda6068ad51654883a99c5aaa3a973bb2f6cd033bc5f8e2f866ac6ce598f1131f2f46580bbf6461f9cb813e3b9286dbf3c53da5a1961a624c"
    $a1="3185a74b789650208d139696e3e42531715b421bc982ddd0b47f28bd1efdc812d0cc2f40b292ba630390ed200041b3c45dca8fa033fe204b3973a5eb8a763219"
condition:
    ($a0 and $a1)
}