rule sha512_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="cb247e9bbd901879f1112bdfb6cddc4899538ed68097e2b4a4d40a71ff90bf9ba26b0cf455bbe295563c61b5e6df122f9e8dd0afac5a599904cd19fe61308ae9"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a7="a057d693d382ea522c9614ead06120a4a8ad74c23f9785af2ee64935b9f95848ad8d0eaf1088d14183cb71a0e1d51aceeccd218d3d270741ab9aa1fa3c0d79d6"
    $a8="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a9="fcd78f7be6deef8efef818081b6a9bd1f09e65d7a9f874192fb5fa6627defa0912fc62957a722a3e99e117369495c2e3d492eadda3e3918e887f31c6940f0eda"
    $a10="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a11="7ce0ba2ea55e20401498f76450481d6d40829c024d70a8317efc91d1477487571e1415bbe8f4ae0e5aaed4c46750f6770d0dab4e24d52d7b68a7c8cad60f2e2a"
    $a12="e6793def3f019b4bcf8450de68864668b63c2ed36c93fc62cc06904d091db6ba9e399d7db4093bb79b9e7cf1c046cf0d20292222eec90666ec8168a77c2bb803"
    $a13="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}