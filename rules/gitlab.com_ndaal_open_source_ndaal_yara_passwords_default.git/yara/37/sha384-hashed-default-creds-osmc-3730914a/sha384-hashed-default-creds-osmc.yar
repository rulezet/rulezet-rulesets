rule sha384_hashed_default_creds_osmc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osmc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd3c55039e3108a10d3ab32e362ac9c78a9b5f962b198b81ee1d684503580396e76aceab20ac13da656b173cb34fd863"
    $a1="fd3c55039e3108a10d3ab32e362ac9c78a9b5f962b198b81ee1d684503580396e76aceab20ac13da656b173cb34fd863"
condition:
    ($a0 and $a1)
}