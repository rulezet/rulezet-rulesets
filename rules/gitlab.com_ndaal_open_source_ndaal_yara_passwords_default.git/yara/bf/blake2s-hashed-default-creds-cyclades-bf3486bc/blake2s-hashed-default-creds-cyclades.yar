rule blake2s_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="382747285d00ccc55f6f066c7922e45d58519650236b5a455329555ee1ecf96b"
    $a1="7b866d188933ccc5dfc6f79bd6366c759f7661ff500626bc1b013b6947eb5831"
    $a2="3b6938e21dfc65365362e70e5672b46f13d2b5a25eccc461c9bc5880f7b341ce"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}