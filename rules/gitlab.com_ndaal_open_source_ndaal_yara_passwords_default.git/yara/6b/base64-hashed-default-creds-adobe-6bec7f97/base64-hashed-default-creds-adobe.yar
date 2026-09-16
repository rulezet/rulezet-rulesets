rule base64_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YXV0aG9y"
    $a3="YXV0aG9y"
    $a4="YW5vbnltb3Vz"
    $a5="YW5vbnltb3Vz"
    $a6="YXBhcmtlckBnZW9tZXRyaXh4LmluZm8="
    $a7="YXBhcmtlcg=="
    $a8="amRvZUBnZW9tZXRyaXh4LmluZm8="
    $a9="amRvZQ=="
    $a10="cmVwbGljYXRpb24tcmVjZWl2ZXI="
    $a11="cmVwbGljYXRpb24tcmVjZWl2ZXI="
    $a12="dmduYWRtaW4="
    $a13="dmduYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}