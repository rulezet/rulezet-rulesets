rule sha3_224_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83db1a30cd194d12e60aea7fd71db341a095f9d4913c34984e142321"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="beb04b428690c3735bb761ee08024d40cada273b6f4cb64c060e99c3"
    $a3="e2fff94df9706d65ab404f1fbf975ae3c9d64deee05b5afc03304759"
    $a4="f7cf7bae5b773cc93e56511ae9d199268b6f9e1a7731ac94a6d646e3"
    $a5="60c9e61cb8512ff3a1f1dc545c3118708f6dc434f6f8342f40eb9c63"
    $a6="5d3537c42ad566601c47c18b803411d9bd0dcc875a98d2126f62b067"
    $a7="cf07e9c1fa80f75a13fc1f921179556d1a519e844123d5e7c7cc4327"
    $a8="eca1b37497244881579be9058e9b7211159de6f1df36b55d22cef8d3"
    $a9="a4d6b17f5d20ce6223a308d938b07a9f3ec093233757eb9e387c963a"
    $a10="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
    $a11="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
    $a12="6eb902718cd28d136036a5b48efc93f098c8ca9db78bdfe5eec117f0"
    $a13="2692bab49e220cb6c4de347c55e2b22779a55080f5dff79c1ccf41b0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}