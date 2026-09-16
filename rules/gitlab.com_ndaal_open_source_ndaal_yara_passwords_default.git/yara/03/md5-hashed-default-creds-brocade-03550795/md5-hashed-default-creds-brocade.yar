rule md5_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="944a4dc4ab890a7bae55a7c55d400960"
    $a1="9549dd6065d019211460c59a86dd6536"
    $a2="5b3aeeefdfafcd5dd385a21d48642d78"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="5f4dcc3b5aa765d61d8327deb882cf99"
    $a7="ee11cbb19052e40b07aac0ca060c23ee"
    $a8="c33e0186aeb031ccc645e31fc5233066"
    $a9="63a9f0ea7bb98050796b649e85481845"
    $a10="d6253984f6416246a10e31efaf7ce0f0"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="d2d47ac5be4bb0127ac168d839c6e62a"
    $a13="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}