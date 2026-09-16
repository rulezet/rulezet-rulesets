rule sha1_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c78e476751ee6bd0056d9d5c6c6b959624784ef4"
    $a1="0cf1243379926bf80f3089d829da78f605276cea"
    $a2="cb160ae3b0a78521c1ad19d22c7d05e4de0c5aa7"
    $a3="cb160ae3b0a78521c1ad19d22c7d05e4de0c5aa7"
    $a4="8b6f1599b3e981940c285c8f3aa63f5d65bfab33"
    $a5="8b6f1599b3e981940c285c8f3aa63f5d65bfab33"
    $a6="455a333004bd3ffa199e082189d7a741f1eb5a4e"
    $a7="455a333004bd3ffa199e082189d7a741f1eb5a4e"
    $a8="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a9="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a10="c451389d15a3a5349dcef1f1c03e0485cebe8715"
    $a11="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a12="6bf49d7c234129c2600d4c70b0234f4e036a892c"
    $a13="462496e262a7466909d4c96a1d1ced97229ec62a"
    $a14="fed87e322da2d305584c0e5800525a0529bf241d"
    $a15="462496e262a7466909d4c96a1d1ced97229ec62a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}