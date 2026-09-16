rule sha224_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a2="78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"
    $a3="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}