rule blake2b_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9806b38fabda70251c32fc04c4ddbb1c535a08480a24ff85be39784986e62eebc05472590452e6188ef42a355905064828d03a96a28e2fd1856a2f5eab8ca85"
    $a1="c9806b38fabda70251c32fc04c4ddbb1c535a08480a24ff85be39784986e62eebc05472590452e6188ef42a355905064828d03a96a28e2fd1856a2f5eab8ca85"
condition:
    ($a0 and $a1)
}