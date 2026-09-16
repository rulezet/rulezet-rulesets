rule sha512_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="dbe2ac714cddf902f6094133afbc3976a3f79cb03b350f21559d81da04b086bb2b414bd7fcf48b751f6dd3b48b2abf0c7d42e59059b4db3432a8ca130323e8e8"
    $a2="0d4eeaa9ffad89bc6cd03dd5b59b5e246601b9329de04e8848ce46244cdccf8aeb98d5b1b77dbcf8122ad452d6b333fd31369c9205b8f4237d11ee40eaf6ea7a"
    $a3="dbe2ac714cddf902f6094133afbc3976a3f79cb03b350f21559d81da04b086bb2b414bd7fcf48b751f6dd3b48b2abf0c7d42e59059b4db3432a8ca130323e8e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}