rule sha384_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a1="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a4="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a5="9f926adb99d65307adc43260aaab27c71af4f8b1c112b8f3b45139eab7ccb9a4afc0569c47fef0c4ba69af737533271b"
    $a6="dc9e656e15fe10c4cd4d42d93b9c221a43ecc62a5302f4d378e9dcd512013653abc3f92c3d2ca6f3d3b138a2463ba60f"
    $a7="0300f04de8446334e084d7cd0a728c1bd46f218eae5aca0989a3b31835e4cf39a7596a0f751fcfea11bfd3109a3ead62"
    $a8="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
    $a9="773d7807eef8dffaf0cffb3a735502f150de9c5e36be5afd6a052942dc9299ee2d71652f3d44aec229ae0799d9158e80"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}