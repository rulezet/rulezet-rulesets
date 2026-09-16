rule blake2b_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5634ee87939a9c6c620708defd8d049ee93d3bbb189bff731946a1600639b30bcaaca90d58b5764988e549d289b22c64ff4e2379290407594f457ef380bdd36"
    $a1="e5634ee87939a9c6c620708defd8d049ee93d3bbb189bff731946a1600639b30bcaaca90d58b5764988e549d289b22c64ff4e2379290407594f457ef380bdd36"
condition:
    ($a0 and $a1)
}