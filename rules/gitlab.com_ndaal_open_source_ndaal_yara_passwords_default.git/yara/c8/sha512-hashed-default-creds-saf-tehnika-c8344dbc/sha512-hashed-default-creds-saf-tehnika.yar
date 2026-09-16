rule sha512_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad8239a8e8161e83fc937d43aa1a7bfe7a3e2a25350005cc550aab0a422c62ce0fe69dd956d0543cab51571bb94782bcc1ec44a99351d309da5e6837703859aa"
    $a1="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a2="324425ea095bbbe73409c1d2f696d122cf53d0005236806c190af038d4723dda08f456dce264946c94da2633e88edb2139c65512ae27d70f4259db2d618a8ea9"
    $a3="c0f50edcf23a4297560dd2bfdd967f31a7b39c5ac60ed6e543f360bcd24188694346ba95e5ed1a8dfbcbce64c693f7998252f8cfe0f5190a2af511a63cf60532"
    $a4="d1a29ffc0c004008f8a6b5baf04a220e902876bf03758bde949c995c8c7fe9bf1db7c4e9d30d42761675d6815022138eccef2a54fc24d586aaa00939f261cc2e"
    $a5="d1a29ffc0c004008f8a6b5baf04a220e902876bf03758bde949c995c8c7fe9bf1db7c4e9d30d42761675d6815022138eccef2a54fc24d586aaa00939f261cc2e"
    $a6="81bba172c1379b4012cee70cce0151517a041591ff726fcddbbecc22c41e4bb49b1b8165bb9b6a23b05e76c0bc3149dd6f129f33d9089195de1e0a42a0487271"
    $a7="bc87235367eb9b67e1f5ffceb7a1e5506d2c3d92fc655b5b75b7b3892e7e7cdbc0f614147df2e89b44846f18f6d83c9246831b542b92ed5ad49cf1f6fbdcf73f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}