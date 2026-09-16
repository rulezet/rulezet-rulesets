rule md5_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="1ec9444ff36213ecc3108c11c63397e8"
    $a3="55c7098ee75090dfb3b9137fcf35bacc"
    $a4="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a5="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a6="4b583376b2767b923c3e1da60d10de59"
    $a7="4b583376b2767b923c3e1da60d10de59"
    $a8="4c9184f37cff01bcdc32dc486ec36961"
    $a9="ee11cbb19052e40b07aac0ca060c23ee"
    $a10="ee11cbb19052e40b07aac0ca060c23ee"
    $a11="ee11cbb19052e40b07aac0ca060c23ee"
    $a12="1d0258c2440a8d19e716292b231e3190"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="96ca9d2f94b871e6933b51800e24e917"
    $a15="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}