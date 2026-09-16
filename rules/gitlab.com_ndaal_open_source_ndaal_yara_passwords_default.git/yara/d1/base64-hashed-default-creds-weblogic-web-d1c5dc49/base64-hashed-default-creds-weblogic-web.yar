rule base64_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="RVhBTVBMRVM="
    $a1="RVhBTVBMRVM="
    $a2="bW9uaXRvcg=="
    $a3="cGFzc3dvcmQ="
    $a4="b3BlcmF0b3I="
    $a5="cGFzc3dvcmQ="
    $a6="b3BlcmF0b3I="
    $a7="d2VibG9naWM="
    $a8="UFVCTElD"
    $a9="UFVCTElD"
    $a10="c3lzdGVt"
    $a11="bWFuYWdlcg=="
    $a12="c3lzdGVt"
    $a13="UGFzc3cwcmQ="
    $a14="c3lzdGVt"
    $a15="cGFzc3dvcmQ="
    $a16="c3lzdGVt"
    $a17="d2VsY29tZSgxKQ=="
    $a18="d2VibG9naWM="
    $a19="d2VibG9naWM="
    $a20="V0VCTE9HSUM="
    $a21="V0VCTE9HSUM="
    $a22="d2VibG9naWM="
    $a23="d2VibG9naWMx"
    $a24="d2VibG9naWM="
    $a25="d2VsY29tZSgxKQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}