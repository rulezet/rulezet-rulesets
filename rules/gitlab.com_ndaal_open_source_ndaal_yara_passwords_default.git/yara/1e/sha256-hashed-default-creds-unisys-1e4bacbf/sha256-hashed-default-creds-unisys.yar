rule sha256_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a1="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a2="56d6f32151ad8474f40d7b939c2161ee2bbf10023f4af1dbb3e13260ebdc6342"
    $a3="56d6f32151ad8474f40d7b939c2161ee2bbf10023f4af1dbb3e13260ebdc6342"
    $a4="548b5bb8af2562d792042b9ba2bac5025de5f360b0e1d9d561c12bb5f1ff00be"
    $a5="548b5bb8af2562d792042b9ba2bac5025de5f360b0e1d9d561c12bb5f1ff00be"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}