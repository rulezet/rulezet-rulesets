rule sha384_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="6edc785d060315bf45341937f9b09fbfa81078bb68858d34758a9e9642fcac66b0f8021f7e223ad96d4632ada6812ac5"
    $a3="6db9bad0dc3514b34221df2fd951015ffa19cb25a36e083eafc28937fbda6af33761eefac930003c37f3f5299ab64a41"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}