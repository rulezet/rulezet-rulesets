rule sha512_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bfee2dd3d8cb03e622357d73a64a293cbc9635f404da9c796b198ce60a0b257f5fd2777b898cf1d91a421a5af6fee527ca6c2de049263f438cd369c7d3513c6"
    $a1="6edd25e9d6ce452871d813f690c368689b3a752f349084e9ff778cf6cb3cab09aae11fac90c437a07515bb2e8f635eb0a1b1dc1f19f1a43e3122181e776577fa"
    $a2="1bfdf7251f58046b93d7e60c65f2bfa54fba4d38b18a2c2fda808eedb97e9b378bd6e30af013ee8c584dac979668ef907d5baab20fb88f8d5f5de05b964d878f"
    $a3="6edd25e9d6ce452871d813f690c368689b3a752f349084e9ff778cf6cb3cab09aae11fac90c437a07515bb2e8f635eb0a1b1dc1f19f1a43e3122181e776577fa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}