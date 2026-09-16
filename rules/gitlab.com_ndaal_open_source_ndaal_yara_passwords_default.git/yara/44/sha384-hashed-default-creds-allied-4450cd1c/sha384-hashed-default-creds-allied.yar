rule sha384_hashed_default_creds_allied
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a1="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a2="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
    $a3="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}