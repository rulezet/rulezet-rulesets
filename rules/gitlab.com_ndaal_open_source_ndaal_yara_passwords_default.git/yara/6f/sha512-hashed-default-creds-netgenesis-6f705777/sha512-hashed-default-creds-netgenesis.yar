rule sha512_hashed_default_creds_netgenesis
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7756d5573e5cb132c51a5dba920730ae147c15cd4dfa8c5c3366918b28d4af720be5a4defe425f7d495d482095a34159ee0eebcc55d7fc2e22858e319ed4c24"
    $a1="b7756d5573e5cb132c51a5dba920730ae147c15cd4dfa8c5c3366918b28d4af720be5a4defe425f7d495d482095a34159ee0eebcc55d7fc2e22858e319ed4c24"
condition:
    ($a0 and $a1)
}