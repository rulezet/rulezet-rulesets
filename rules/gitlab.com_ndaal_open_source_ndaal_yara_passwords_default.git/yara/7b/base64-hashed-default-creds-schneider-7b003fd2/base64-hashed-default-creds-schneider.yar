rule base64_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="ZmFjdG9yeWNhc3Q="
    $a2="ZmRydXNlcnM="
    $a3="c3Jlc3VyZGY="
    $a4="Znd1cGdyYWRl"
    $a5="RmFBbVU1cDJGfg=="
    $a6="bG9raQ=="
    $a7="WmZUbGp1YmxzeA=="
    $a8="c3lzZGlhZw=="
    $a9="ZmFjdG9yeWNhc3RAc2NobmVpZGVy"
    $a10="VVNFUg=="
    $a11="VVNFUg=="
    $a12="VVNFUg=="
    $a13="VVNFUlVTRVI="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}