rule md5_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd268bd826d9947ca1feb5e9851a963d"
    $a1="dd268bd826d9947ca1feb5e9851a963d"
    $a2="29e7396b6b7e8b8ab20daabcde1c7732"
    $a3="29e7396b6b7e8b8ab20daabcde1c7732"
    $a4="62608e08adc29a8d6dbc9754e659f125"
    $a5="62608e08adc29a8d6dbc9754e659f125"
    $a6="827ccb0eea8a706c4c34a16891f84e7b"
    $a7="a571d969c8661fb0342afd08e571dfa0"
    $a8="268e27056a3e52cf3755d193cbeb0594"
    $a9="a571d969c8661fb0342afd08e571dfa0"
    $a10="0c23a8bf29a191f18aee814737e2a6ec"
    $a11="63a9f0ea7bb98050796b649e85481845"
    $a12="96ca9d2f94b871e6933b51800e24e917"
    $a13="63a9f0ea7bb98050796b649e85481845"
    $a14="827ccb0eea8a706c4c34a16891f84e7b"
    $a15="1316379096c85e48ae3c8426e1536ed4"
    $a16="ea9bb3aa950723face73423802625074"
    $a17="ea9bb3aa950723face73423802625074"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}