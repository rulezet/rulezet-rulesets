rule blake2b_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bddc3a7e69780937eb8b5fc52a605ec0a498c218c97588494ed74df7d5e4240f3c666b50d3c019c2fa76f3973935e64e17ccb321e4285f142b7b0cd44dca643"
    $a1="6bddc3a7e69780937eb8b5fc52a605ec0a498c218c97588494ed74df7d5e4240f3c666b50d3c019c2fa76f3973935e64e17ccb321e4285f142b7b0cd44dca643"
condition:
    ($a0 and $a1)
}