rule sha512_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ca825ca637138f338b75f5a3a1fa29ba7048e9bcbff41c48acf8ab7aa308e84b910e1969087385917213b89278af76606f5ca3150652a7b4537afcb28197226"
    $a1="2ca825ca637138f338b75f5a3a1fa29ba7048e9bcbff41c48acf8ab7aa308e84b910e1969087385917213b89278af76606f5ca3150652a7b4537afcb28197226"
condition:
    ($a0 and $a1)
}