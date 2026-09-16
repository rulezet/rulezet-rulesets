rule blake2b_hashed_default_creds_team_xodus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for team_xodus."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ee0048a5fcdebe2afe62962ca40b9e76ac7289928307045f562a55fef28a6cbe276f9a53b5af31bb7586523c58f62b4f8a4d47efd15023e1fad37de836e049b"
    $a1="7ee0048a5fcdebe2afe62962ca40b9e76ac7289928307045f562a55fef28a6cbe276f9a53b5af31bb7586523c58f62b4f8a4d47efd15023e1fad37de836e049b"
condition:
    ($a0 and $a1)
}