rule sha512_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97a38fcd6afd9b1f06093ebb718d8cd30c582c61341528eeb1712cb04a12dd5b92609fe45ef312b5d1f2049c3a77ca3da444fe8d2e890b6cf37bd0ae1376d4ca"
    $a1="8ba5c19a95974328afc1e856c2c15cb9278453433ad44985dcd501e56f9acfdf95e4cc1edd1b83a2df359abdcaab35c1ba4dc0918641733c6b153ae6c3b872c3"
condition:
    ($a0 and $a1)
}