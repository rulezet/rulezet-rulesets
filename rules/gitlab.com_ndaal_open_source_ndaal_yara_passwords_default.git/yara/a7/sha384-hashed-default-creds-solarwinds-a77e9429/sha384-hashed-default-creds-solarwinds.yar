rule sha384_hashed_default_creds_solarwinds
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for solarwinds."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91212aaf321c3b4d23503cf40e5b8f01afcbaad1778e172854024e4fd6e4e4303ecc09a37be2a36cb4db97b46564c81a"
    $a1="1484de0772e0b53151ead333a852c1a103f89583de67f68f12ca6190e6c063a093e6a4ea33f99e7d637d26b73b5e2c27"
    $a2="a7591433bd34df4d505df3b556313a14f89c879169c254a4d23df9b6e5b94feaedfbe4b9475ecbee98168bcd55c605ef"
    $a3="a7591433bd34df4d505df3b556313a14f89c879169c254a4d23df9b6e5b94feaedfbe4b9475ecbee98168bcd55c605ef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}