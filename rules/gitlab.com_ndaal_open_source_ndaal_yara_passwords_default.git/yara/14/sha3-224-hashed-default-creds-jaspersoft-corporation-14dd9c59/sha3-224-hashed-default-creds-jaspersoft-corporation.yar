rule sha3_224_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a1="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a2="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a3="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a4="e000396654a89fa993f47db2cabde37b5583705c99f6c953396af3b3"
    $a5="e000396654a89fa993f47db2cabde37b5583705c99f6c953396af3b3"
    $a6="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
    $a7="4b056879bc7c26ac3b7f5414bda95b28079acce79a708f62cc510843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}