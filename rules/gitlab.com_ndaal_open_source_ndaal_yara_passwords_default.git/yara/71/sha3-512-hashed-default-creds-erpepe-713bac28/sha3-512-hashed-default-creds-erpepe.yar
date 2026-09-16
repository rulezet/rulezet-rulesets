rule sha3_512_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3df48ddd03850d978ca8176f69ad856e99251172b1e27f1b2bbe75578dd6a6ab7dc7d7ea12454f0a24209a7bfea1b3a721371cead50966ae279682931334e4c6"
    $a1="35459a74cc55a091fa26935dc48656ee60512e4e7817122db1a58330bc5f2b1733061df22d26b44a0dfca727d66c23cf67fc6b3608a4a88a7c9bff2e7e3b29c5"
condition:
    ($a0 and $a1)
}