rule sha3_224_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d7aa7e09d0857f35411eaa9edbb6e409c55c7561395baf47df4c1ec"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="335b9b5fb1b2e8a6ac3f8aa5544661184010b3c00d5d93da2ec9c268"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a5="2268df243f3ba7aec970f4326b184d5db233b57082c465d9ffcbc185"
    $a6="5789eaaa22f199b60eb6fbf90898db050c4c9b34059f7f5a0efecf23"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}