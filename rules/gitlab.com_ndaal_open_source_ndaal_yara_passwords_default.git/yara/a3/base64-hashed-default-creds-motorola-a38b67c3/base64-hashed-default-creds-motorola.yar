rule base64_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2FibGVjb20="
    $a1="cm91dGVy"
    $a2="YWRtaW4="
    $a3="bW90b3JvbGE="
    $a4="YWRtaW4="
    $a5="cGFzc3dvcmQ="
    $a6="c2VydmljZQ=="
    $a7="c21pbGU="
    $a8="dGVjaG5pY2lhbg=="
    $a9="eVpnTzhCdmo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}