rule sha384_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="925869fbc5428e20cc1fa0cb6494b04613d49a86f0e83954675b1f720207b0a725e0ff7cc0b05fe835dab5fb07821a43"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5d62d62372734f5f447cd35304786d0f21f71d2511419eb941aa9b48109109662c0c2d360f5bbcb537f12e0cbb157eff"
    $a3="63fc52ff0cf52087b8b5fc53850973d288f6982570d4b469c8dac1e963a93772d928ae1350913b121946085f0a63b853"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}