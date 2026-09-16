rule sha1_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a3="9993c0ee288292078ca1a18dad545a06622583f3"
    $a4="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}