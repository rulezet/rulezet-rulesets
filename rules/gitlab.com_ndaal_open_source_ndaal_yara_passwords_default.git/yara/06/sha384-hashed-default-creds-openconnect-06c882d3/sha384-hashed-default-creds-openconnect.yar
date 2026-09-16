rule sha384_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a3="0ff64f996d8a96a38eb1b6517c1b589c5828de0aedee8c3a5f88be0be123f2444decd406693afefc6f004212be4c5013"
    $a4="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a5="431b73020c73a6b38313f9f5624cf71fa4ee55f20773c892ffcc3655a952fcaed2a17b07098af4d13b64b1f88e7005f1"
    $a6="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a7="62c2678811252ad18f03bf17e8da50d004cb340700bf2bd04ee81629a0ce31f8542a0287f8dcef19f782d7106872d7c3"
    $a8="007ac647d19f81bbd8b82e851a6e888587598792256c2e011f5b4a498d6bd3d60164aaa31d4462dab6c38fb9f8f424a7"
    $a9="4e807e812394357ed9e0aeb1ea7094f09d1acb0fc095294ebeadceb294c2a2952b802521c935e70fbd32d52818c6d452"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}