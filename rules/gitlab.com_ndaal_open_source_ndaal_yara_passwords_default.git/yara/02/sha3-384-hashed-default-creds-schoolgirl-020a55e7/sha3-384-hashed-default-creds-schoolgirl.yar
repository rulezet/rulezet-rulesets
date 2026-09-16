rule sha3_384_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce3f0fc410e6ab5a43f9c591d50f3aa08e5992b758d9b29da399534f6d8b3c12d4b3e88a70e5c30aa51f72bb4daed377"
    $a1="02342ddfd0940940fd4077541960670dfff207e2a2bd3e7b9f5b41268d6359af14a1547e34d1adcc70b47851efe5cce4"
condition:
    ($a0 and $a1)
}