rule sha384_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="521e2117c8323e893baa0ce500a513ba635ad96fe3156a317c77924723aaa5859debf6b6e69ba44b7a2ab4724091899d"
    $a1="439ece558fe24b03b63ce900cfb5e0bc894bfa395361307b42c94e8b1b03298cc60419aee4b09e0c128aec38638602bb"
    $a2="0bf3b54dc38a203d2213b18247a7b72c22aeb37c969207af6df6bc8dd7f08accb84fe98e32445cba70a2653c9f7fdba0"
    $a3="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}