rule sha224_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a1="704878b930e6c0a1bf9c2534c9271d6d09c85956f5532aa21b23ac30"
    $a2="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a3="c573581f23014a220ce810c6eed001ce74cf7b82c76f37a7a6bbb855"
    $a4="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a5="192a06d20b1a067cc25d4916200752c0903521fdd342bef03961284a"
    $a6="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a7="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a8="bc4c7b249289acdc09f7cd84537311182f71a4c4b8a391a870d55929"
    $a9="a976fa8a05671043deadbfc0d50a15e9adf48d47361991e7b0452a0b"
    $a10="557f89c384f7385be18c3d14c893f72029f8abab7ccd0663f4b49474"
    $a11="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a12="0af5f61619a226b4a59dbab983fb0027d12dbe9fb438e89835539982"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="a7470858e79c282bc2f6adfd831b132672dfd1224c1e78cbf5bcd057"
    $a15="9b32cc942b73c884c90a739a20aa5c379c6fa6a7832ea521d5ffeaa7"
    $a16="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
    $a17="b573f6c18a1ec9e54b18f686bc8e143978cf67f317facf0296d9620d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}