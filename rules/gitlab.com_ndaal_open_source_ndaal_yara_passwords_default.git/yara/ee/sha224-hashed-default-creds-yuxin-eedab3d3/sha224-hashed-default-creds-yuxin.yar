rule sha224_hashed_default_creds_yuxin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for yuxin."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a1="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a2="af6b13f26a1b52f2c7bfcf59ac1afbe6531cfc5d421421c73251a8de"
    $a3="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}