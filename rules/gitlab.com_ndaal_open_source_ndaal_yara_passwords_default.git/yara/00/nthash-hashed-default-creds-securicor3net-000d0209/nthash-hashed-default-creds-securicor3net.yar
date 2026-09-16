rule nthash_hashed_default_creds_securicor3net
{
    meta:
        id = "6OHAfTZ9SBG8pWKnnU9LVo"
        fingerprint = "25022bb8132ce6c07a463a1257f87446efbce794cc9e51f8befa2f1986684626"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for securicor3net."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99d479d0a424c9ecbcb67568c4889239"
    $a1="f938b53b982f22cd6b1c14ae10665480"
condition:
    ($a0 and $a1)
}