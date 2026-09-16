rule blake2b_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48963e6f0f72cc8bff4cdd9c516562bcd3ea46997321e13a2ff4446aed6aa09ec9655e32310d13a478d4259c7a582958def0d27ab658a5229e34a4bd99dbed78"
    $a1="48963e6f0f72cc8bff4cdd9c516562bcd3ea46997321e13a2ff4446aed6aa09ec9655e32310d13a478d4259c7a582958def0d27ab658a5229e34a4bd99dbed78"
condition:
    ($a0 and $a1)
}