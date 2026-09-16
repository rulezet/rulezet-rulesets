rule md5_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="202cb962ac59075b964b07152d234b70"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="29379c264d9967370094c2e5cf49ddea"
    $a7="2984ad79c59a7451dd81c713ac273d5f"
    $a8="697efa94ad1e665c4d0edd4c810db6fb"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="33a6e9c48d7a2df7afaa5b0afccec7a5"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="81dc9bdb52d04dc20036dbd8313ed055"
    $a13="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}