rule md5_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17d43309750298c14488d50f56fd2b8f"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ed45840f6a6415ca5eb50ae607e9449f"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="62f45890cd48195be8e9318aa383456b"
    $a5="336ebbb2179beaa7340a4f1620f3af40"
    $a6="333d3e2dd98f46786c6716cb59995fc1"
    $a7="2ea7fe2bd051ec076a226b7dab76aaa3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}