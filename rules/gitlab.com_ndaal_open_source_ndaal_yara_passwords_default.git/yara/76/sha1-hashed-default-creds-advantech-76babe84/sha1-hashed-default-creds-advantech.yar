rule sha1_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="b72cbf84194c13b0c24d8721d5fd4f99acf17b21"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a7="e96857c58f716104caead648ee6aa61ab8e41cdc"
    $a8="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a9="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a10="70352f41061eda4ff3c322094af068ba70c3b38b"
    $a11="9f8a2389a20ca0752aa9e95093515517e90e194c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}