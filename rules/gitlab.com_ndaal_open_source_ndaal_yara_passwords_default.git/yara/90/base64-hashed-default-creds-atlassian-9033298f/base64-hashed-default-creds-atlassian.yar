rule base64_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Q3Jvd2Q="
    $a1="cGFzc3dvcmQ="
    $a2="RGVtbw=="
    $a3="cGFzc3dvcmQ="
    $a4="VXNlcm5hbWU="
    $a5="cGFzc3dvcmQ="
    $a6="Y3Jvd2Qtb3BlbmlkLXNlcnZlcg=="
    $a7="cGFzc3dvcmQ="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}