rule sha3_224_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38d451cef0eed09b331be920a49c913572c59e9c1e7af5d1899f70c5"
    $a1="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a2="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
    $a3="b7749b20d3cdfb004991b884ff3e9f79aff9a7b83bbdf1e2522628d7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}