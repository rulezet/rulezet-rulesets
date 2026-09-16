rule base64_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3lzdGVt"
    $a1="cGFzc3dvcmQ="
    $a2="aW5zdGFsbGVy"
    $a3="MTAwMA=="
    $a4="c3lzdGVt"
    $a5="bW5ldA=="
    $a6="aW5zdGFsbGVy"
    $a7="MTAwMAk="
    $a8="c3lzdGVt"
    $a9="cGFzc3dvcmQJ"
    $a10="YWRtaW4="
    $a11="MjIyMjI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}