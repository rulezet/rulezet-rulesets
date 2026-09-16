rule blake2b_hashed_default_creds_airaya_corp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for airaya_corp."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f7a4b2115c9555498caa7e3dcb920db55ed55e7c7365c6309985a2bae2ab785682e32be6e5eaf31dcbacf9b3db09633e64af0c675897ff2494181d5c2744cec"
    $a1="5f7a4b2115c9555498caa7e3dcb920db55ed55e7c7365c6309985a2bae2ab785682e32be6e5eaf31dcbacf9b3db09633e64af0c675897ff2494181d5c2744cec"
condition:
    ($a0 and $a1)
}