rule blake2b_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4037a63ec412209574e54ff977cf321414520e39e89a75e11a0aaadd732f5fb591bfb968a7564e1d172ef5d51ca932f5838f4be0cfadf45e61d439b31b49bc4b"
    $a1="cf707e79308f5867c85a95aacf508aff835039724a38cff3deda189d4a7026fbcee2b666fbcdfe1fb0d7b7e3b76710a2ecaf5daa97e027d9a1bd63d4b1fd3107"
condition:
    ($a0 and $a1)
}