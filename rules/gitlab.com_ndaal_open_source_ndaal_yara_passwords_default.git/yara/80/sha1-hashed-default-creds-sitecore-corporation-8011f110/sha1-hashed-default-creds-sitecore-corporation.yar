rule sha1_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
    $a3="9f56d9b292b55162ca3999b56f054b407a2ae67e"
    $a4="e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98"
    $a5="3d7346140016dfa40c770fa19ba722af2eb48073"
    $a6="3c363836cf4e16666669a25da280a1865c2d2874"
    $a7="eb7bf420a2ae1f2aabda8b343c7d9a4119e3eb76"
    $a8="07c342be6e560e7f43842e2e21b774e61d85f047"
    $a9="5e6a4f171a2ae0ad43b1589c46ec889cef730aae"
    $a10="6b0d31c0d563223024da45691584643ac78c96e8"
    $a11="22d66954ca280d9599497b28512fb7999f3fdd13"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}