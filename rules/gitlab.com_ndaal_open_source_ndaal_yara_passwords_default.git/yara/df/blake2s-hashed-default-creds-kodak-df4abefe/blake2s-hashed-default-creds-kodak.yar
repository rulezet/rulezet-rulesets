rule blake2s_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a1="b9aa61b65cbd2fd9e69bd7561082d6848cefc41937da481dc38cb525d8a22a6d"
    $a2="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a3="ae7e5e149aad2e9a2be604f920e8520f924a29632b43d734a6e81c773605a0d8"
    $a4="1f24da37059976cf07646827165fb93c9ed56aed19bdded1d0805756a279d722"
    $a5="e17fa0e023d886895f44ccc9c2f6642cddd5f6f8b1dc8da8a78ba4ffc733d15b"
    $a6="d92248532a1bda4f87c76748e5dd87350b1613cbbedd7970c54dbb98e2aeabc3"
    $a7="a071a59b54ffb10629f3ab2165574be5683603a04701ad5d0210499a93d7fdb2"
    $a8="897ff9bf3f0989c89e46835e7685a4a0ffcb6c483e9a1797e11c28d705d74987"
    $a9="897ff9bf3f0989c89e46835e7685a4a0ffcb6c483e9a1797e11c28d705d74987"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}