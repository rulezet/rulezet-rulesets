rule md5_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b8ced15fc068340481764731b8f4b98"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="b105e7225fca404e542be5811a128e55"
    $a3="038315ff8406b92d4ac9af43f1cc3fec"
    $a4="b105e7225fca404e542be5811a128e55"
    $a5="e0d3878bf82d4523590533b4f3973f39"
    $a6="47efa148b3f2428ae072e2a66c779e53"
    $a7="9cf2903aac6bf5fa28745eb7ece79c0f"
    $a8="59a8add95efb4a6974aad6f7580a13f9"
    $a9="59a8add95efb4a6974aad6f7580a13f9"
    $a10="a1fc0b4dc4eb11d1b8fffeb489b6157c"
    $a11="4606b4ad44b3a29a938ca4bae57abe08"
    $a12="f0fc6dc45ccea5e53fe9e0d96cf565af"
    $a13="f0fc6dc45ccea5e53fe9e0d96cf565af"
    $a14="e86f1924366d5e2d9bede7e97584760b"
    $a15="18fb3358c071e8cafc01472c04f9460e"
    $a16="a99accb226354ab7230fa3258b03c4f5"
    $a17="a99accb226354ab7230fa3258b03c4f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}