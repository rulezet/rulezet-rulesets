rule sha224_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="96ecf9f93354b91ef86f84e4e3df1d07575ab8d510c8147159166e4c"
    $a1="8ab4ceca62bb85fde84d08431d00c9a4d143b476f4923ee7e043f58a"
    $a2="b759497cf50772b2452434b3983eebcc1772f1e03bbd76dc2a139da7"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="17b20f7839c9cd33b72030805610ca375c8d2463bce1fda96c13b87c"
    $a5="c45289d57b8855d6ac92496bdcd7ae23d94a7f0a70d5970453d60f30"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}