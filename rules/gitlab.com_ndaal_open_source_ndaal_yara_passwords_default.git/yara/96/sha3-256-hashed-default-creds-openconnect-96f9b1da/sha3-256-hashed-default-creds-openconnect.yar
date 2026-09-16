rule sha3_256_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a3="19d7cd70d22058fd1b9f31b78d1a1ad90cdf9541a1b17ac7b2cd9a62e8ac2bb5"
    $a4="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a5="031e7b87a990d87f7ede6d67a6d166366a2c222428de5825ddff1b42f77a684b"
    $a6="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a7="90837cedf4bd5ac7a1a4a0d95ca81a172a7ff25a1630f158abead0653101079d"
    $a8="0ba89b0f374bc15fbc2f39882ba5c4d1db59517683acfc7785022de3d19fd4fe"
    $a9="db83f91b7812a78fae5624a47d23297827bc5c1a34cb240c12aeb01278e55fa4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}