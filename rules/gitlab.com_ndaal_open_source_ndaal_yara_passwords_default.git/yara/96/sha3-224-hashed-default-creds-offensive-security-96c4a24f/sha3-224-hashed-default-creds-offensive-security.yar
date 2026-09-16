rule sha3_224_hashed_default_creds_offensive_security
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for offensive_security."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3ca50a128c23ca92e0209e50b70b374aec795064f8f331b6708aebf"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="ad0d5bca596b15309b523076915d9fbcb0065f1de56180305c534089"
    $a3="ad0d5bca596b15309b523076915d9fbcb0065f1de56180305c534089"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}