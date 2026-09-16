rule sha384_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a2="bfb6d0743bfa948afda25ea95b22a9e5c7a9fe05edda710f449c3a48eafd648dc7280b3614d59454e7ca1dadc9fd193f"
    $a3="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a4="da46068206fe2c7cb44ad48360ff1f4508e083d06beda566189de20b31ae7d6bb3c9fa4221f3c2582791a1c76e76ab1a"
    $a5="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a6="bd7d21d20a3ef1cc135b93a5089c80da734b38e5ba80a9e44fcf63e4268d409cfb9ddde2f05933840a9c430f06a1c2f2"
    $a7="e8d3610af1f69386211907c916abaa27f50ddadbf94af845750fbc230a2d023a89db2fea55fc2115e0e05c60f03f2774"
    $a8="7aee27d886b37b7215aaca74429b3886f14c9af360d86f9bc8307bb2a0bfb2e14e01766d75dd552efa5d55064df29f7f"
    $a9="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a10="7ffd57cbcd46bc1359d376fd84a4301e2937322afdfd716933db49a5aae2aa59511dc8d3143e2cf55d00ef0135b1a7cb"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}