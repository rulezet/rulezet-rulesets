rule blake2b_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a1="f5b72cdd6f114cdfac80d23f52b9ccbb12c0d065362b039f392391effe37224748a410db32229647bc0bc876292b2bfdecba4a63209398354a665bed6ceb4427"
    $a2="98b4a448b288bb9f66e508139df2576b4101285caccf6db6c65ae82fbd9790cd57d46789f86907741add261719c41791f5607b4a5cc0002ff0f594efe636e3eb"
    $a3="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
    $a4="8ba3a9ba1f70a08a652a6c98bea64a11dced25819903e5f21eed7db692fa1e382a3f4e9d0c24e18baacb42c7cef6c35349a61804451bb2f208623d39e8a26986"
    $a5="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}