rule sha1_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="60f39b672c37678733c0751ba95a7d4459a4fa26"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="9bd11ca220d0747adbf182a536c24a12790c36a8"
    $a3="f69e7426b2f473178b7f09b04539ec49337fd723"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}