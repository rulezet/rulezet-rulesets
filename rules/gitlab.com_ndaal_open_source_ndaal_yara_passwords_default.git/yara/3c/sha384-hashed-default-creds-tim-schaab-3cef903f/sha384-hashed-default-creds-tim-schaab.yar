rule sha384_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="667332fb92cbc368815b6668d52f2261b3ff4d7d0f9e52a0fbabb37f261c13c1a3985abba04d322580c7d48060f7400b"
    $a1="52aae9ef3de689f47d9ad60e13b8f52849e53baca96c495efdd6dca4abc7d3feebf571e2f1da7becb2c1348362a91407"
condition:
    ($a0 and $a1)
}