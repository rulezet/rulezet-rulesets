rule sha512_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
    $a1="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a2="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
    $a3="7ccf8f59491f577b1405d4f1a6228d73eb7d45e67f156bf5459566307e72325a5318d85133c3078fa74cbaa04f5b0e92e681a09e3e3c87ba596e8d8005eaf0a4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}