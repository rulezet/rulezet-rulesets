rule base64_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="SmFuaXR6YQ=="
    $a2="Z3Vlc3Q="
    $a3="SmFuaXR6YQ=="
    $a4="SG9tZXBhZ2UgUGFzc3dvcmQ="
    $a5="MHRo"
    $a6="dXNlcg=="
    $a7="SmFuaXR6YQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}