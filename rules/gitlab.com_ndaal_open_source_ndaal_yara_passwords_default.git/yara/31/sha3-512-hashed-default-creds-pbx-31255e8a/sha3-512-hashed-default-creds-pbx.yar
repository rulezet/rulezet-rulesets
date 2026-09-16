rule sha3_512_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81c677288c3070c810025f7de9212f2089d9d23917c49cb791d368dc086d7ba348fc2f11a88855e6f6a48a6e6528f10d7476759c0a51a169cbe0ba167c9785ff"
    $a1="00ec7004fc7306dcdb8cda65db82cd35a68b6c9146a2afc84e112c97c71f8e016fbd113fed86326fb3787dcb13274b25e3f909c58fcfdcd13c18e82905f1f464"
condition:
    ($a0 and $a1)
}