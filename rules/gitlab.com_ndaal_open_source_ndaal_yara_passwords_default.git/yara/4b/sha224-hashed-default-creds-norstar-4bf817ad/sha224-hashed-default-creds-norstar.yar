rule sha224_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e4b20df5577bb098273e488f2d8905f76f3a636abaa475a2905f5ece"
    $a1="68fe22dc09250aa713a1fb5a00d225f01129c5b0f25f829b5ff67c54"
    $a2="38edc88b3ab1018661a57dd4f8ec4bc52e5363b9cb1dc3f8df7c8fa0"
    $a3="2e6f0d7df8589a2e439a62909336e41a2c582096301843337eed1478"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}