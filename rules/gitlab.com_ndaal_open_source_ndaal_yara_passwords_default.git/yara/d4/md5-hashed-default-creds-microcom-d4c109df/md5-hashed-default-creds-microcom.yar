rule md5_hashed_default_creds_microcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microcom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="41869568556ac8f1b3d86aa0eb97b303"
    $a1="54b53072540eeeb8f8e9343e71f28176"
    $a2="697efa94ad1e665c4d0edd4c810db6fb"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="0baea2f0ae20150db78f58cddac442a9"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}