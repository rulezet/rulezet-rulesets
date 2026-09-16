rule sha224_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d1118f1078da1becbff39f24585160bd8d1cf2d41326782f961f52a"
    $a1="7c85fdc099f0480fd1cf258c0ede273a9822f9978b7c2404a0890f6e"
    $a2="8d1118f1078da1becbff39f24585160bd8d1cf2d41326782f961f52a"
    $a3="81b29c67d513aa0767854fc82575b2b48f719e6cb5ddd4aa7aa86570"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}