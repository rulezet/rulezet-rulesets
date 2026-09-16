rule sha512_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="ff9afc6ec2604a9cd14bf322afa7e58fcd52198a5e3ec6b2ee12529ca1d0d4ed08729a9efdb1e66d45343b34ea2d448ad688fa7ea847f4fa020ea988cb6c496e"
    $a3="ff9afc6ec2604a9cd14bf322afa7e58fcd52198a5e3ec6b2ee12529ca1d0d4ed08729a9efdb1e66d45343b34ea2d448ad688fa7ea847f4fa020ea988cb6c496e"
    $a4="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a5="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a6="54927c09868c20229c8575d1bf608bc204c693faa30a63908f9f570382f353bd721f6a5969a1d8a47557fd5947f16c2e9ca5fb8655e1f3c87cb51aa06f5f5a00"
    $a7="0925c768a48dcdcbc8b4b29802775443243ba31d59624a6796779ee7c85352313e425332fa236b1e6f53d3c905e3f672f2e7fe2eee8603284730999a57d78ada"
    $a8="fee256e1850ef33410630557356ea3efd56856e9045e59350dbceb6b5794041d50991093c07ad871e1124e6961f2198c178057cf391435051ac24eb8952bc401"
    $a9="3aef3d311fd74b9e45edc2bb9d9f85b94056cd4dd2ef724541397a1ba4bb7a1693d2f6480d3c3e58e8fea841db6ac4ad2491809d245e8863900205bb99b884b5"
    $a10="d265752d58a2c98791a7affff1395b873f3bd4f4298e5cc3c40347f4d84158cbbad15b7b22deea56a56a22a2d9af2198a51ff42605757a9d30f39039b14d47c8"
    $a11="d265752d58a2c98791a7affff1395b873f3bd4f4298e5cc3c40347f4d84158cbbad15b7b22deea56a56a22a2d9af2198a51ff42605757a9d30f39039b14d47c8"
    $a12="ebe0372ab9e479ffcf37de8d8807bb063aebe962918b8bb6114add1f1a3b1061339ef4499062176415851f1d33f31818869ed99d3442bca481a17f5afaf3fe1e"
    $a13="ebe0372ab9e479ffcf37de8d8807bb063aebe962918b8bb6114add1f1a3b1061339ef4499062176415851f1d33f31818869ed99d3442bca481a17f5afaf3fe1e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}