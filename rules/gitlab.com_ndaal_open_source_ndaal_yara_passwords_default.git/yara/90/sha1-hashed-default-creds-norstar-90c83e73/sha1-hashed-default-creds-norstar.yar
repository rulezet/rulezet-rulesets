rule sha1_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bc37ca9b9af504a1345f74802083c0f57598cd8"
    $a1="ccc855e748bb342ffbedb1c2b98009d5cdf3fa18"
    $a2="7b79979f92760a866a10f43c74fb37ed6013e482"
    $a3="2129b66413b050500f56327d764d79a3c5906078"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}