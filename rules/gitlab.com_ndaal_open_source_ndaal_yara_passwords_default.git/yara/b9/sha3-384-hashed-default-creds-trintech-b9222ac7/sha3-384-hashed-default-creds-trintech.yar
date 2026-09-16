rule sha3_384_hashed_default_creds_trintech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trintech."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="196cd38b3751770b63e1611bcf669cd373637840035fe7542ba148d00d1bd088f07f2b6ceddb1001d91baddd6f8e8bd3"
    $a1="7719fe51b1829509bd3ee190bd1580d4d28d39646e9468440ce339604fe2c04f3f35ccc203076f89c62bb43f6e971636"
condition:
    ($a0 and $a1)
}