rule base64_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZmFjdG9yeQ=="
    $a1="RmFjdDRFTUM="
    $a2="cm9vdA=="
    $a3="U2VydjRFTUM="
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="dXNlcg=="
    $a7="cGFzc3dvcmQ="
    $a8="cm9vdA=="
    $a9="Zml2cmFubmU="
    $a10="YWRtaW4="
    $a11="YnJvY2FkZTE="
    $a12="cm9vdA=="
    $a13="ZmlicmFubmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}