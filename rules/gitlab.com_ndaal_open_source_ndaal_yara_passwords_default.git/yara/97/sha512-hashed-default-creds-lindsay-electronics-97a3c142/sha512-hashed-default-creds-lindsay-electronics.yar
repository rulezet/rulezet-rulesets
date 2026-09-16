rule sha512_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
    $a1="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a2="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
    $a3="254a072f0b44550a4e81a7104e8293d45d3860a39975f2f1ab4c7edee5f733d9871c6b3715ea6d510445c88c9c3f13c00e0f4781475e7c2a1f764e0b7c195f12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}