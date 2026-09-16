rule sha256_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a1="3df59c6f0ba35199c606b079a1e71879a6cd454cf40be87958bfd7ed0e364f5e"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a5="b512d97e7cbf97c273e4db073bbb547aa65a84589227f8f3d9e4a72b9372a24d"
    $a6="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a7="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a8="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a9="5ed8944a85a9763fd315852f448cb7de36c5e928e13b3be427f98f7dc455f141"
    $a10="2f0860b3cc6d396499ef3be04866af3b885f4c1934e77c346f0ce2443ff0f640"
    $a11="2f0860b3cc6d396499ef3be04866af3b885f4c1934e77c346f0ce2443ff0f640"
    $a12="a4fbcda21d33b11f38ee0f50d2b21ba3c56fd9fccd5444846a46fc7d16fb63d1"
    $a13="cef54334edb669f337fd35144f5832c25e9adb716a7f3f57ee016d6212300c26"
    $a14="f072c365ed726ea6c0e1749227c422b9b2bd63ac130644021d82515afa9ed9be"
    $a15="f072c365ed726ea6c0e1749227c422b9b2bd63ac130644021d82515afa9ed9be"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}