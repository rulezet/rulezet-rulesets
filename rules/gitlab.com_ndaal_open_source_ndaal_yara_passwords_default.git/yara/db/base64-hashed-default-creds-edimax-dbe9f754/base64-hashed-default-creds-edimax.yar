rule base64_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="MTIzNA=="
    $a2="YWRtaW4="
    $a3="MTIz"
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="ZWRpbWF4"
    $a7="c29mdHdhcmUwMQ=="
    $a8="YWRtaW4="
    $a9="ZXBpY3JvdXRlcg=="
    $a10="YWRtaW4="
    $a11="c3VAcHNpcg=="
    $a12="Z3Vlc3Q="
    $a13="MTIzNA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}