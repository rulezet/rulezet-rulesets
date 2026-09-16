rule sha384_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="629d925ca42d071cac10e75427bcbd031d4f4f0d83ca3639400a335990ec7a1707ccd5671050fd4ba2f9bf88cd08689c"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="0e754d5204dbebc67da1d279fbf89a6ae7000c0d2c12c802a42a99cc94c80a16ab49b346c7a118b5dacbe4fd88cf3f70"
    $a3="f24c2cef56c88200fd45a92ef453979e510e6979aa37a2a16eafe3d27a2c8fbc8d82b4ad8102e590c645b806ca8b1f02"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}