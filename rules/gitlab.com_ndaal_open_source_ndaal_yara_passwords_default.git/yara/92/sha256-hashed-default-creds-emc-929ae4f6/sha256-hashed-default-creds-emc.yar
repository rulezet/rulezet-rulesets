rule sha256_hashed_default_creds_emc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="90d54bfba6ce83053e381a1f25ef79623ba173dd2da1efd0d8012c59ae35c469"
    $a3="0b2087647dbbe70aabe73080cff1b0d8c57abb814b98e3be32b981afbb4e4154"
    $a4="a732f6cdd70a5011b295ea183f68822491eccc0b861dbb14d63023c6d83f0ba0"
    $a5="d6c23081e62be3824f64d440f8857855d0f4743a0551012ab1ed00960faba149"
    $a6="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a7="3f307a9a1f690cbb0898051c943548043edb143d777248190a9efe613624f7ea"
    $a8="a6317ad3260928e8a244330703cb86786f823e85ed1e20072f28163a3e99a984"
    $a9="3c29ab9823defa4c1e4a77dd78e3a8a4fa29e7942401a66f4734fa2f7a0c1bf9"
    $a10="4e20152f0b52d424815059d5cc82ba9b9413b82c9ffa7fb09b4a57de7388cd0b"
    $a11="235e1ec32d2db775a74afe5994b9de8a16fc3df5a80d08c9b8d10606650e3d55"
    $a12="b26c1994a343adb04d4fb3d253e0bf29263fe36755cda2b7754ef65691532582"
    $a13="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a14="057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86"
    $a15="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a16="97e5a2f661a8289c12dbb8f8a71db88c874ce235f038e2aa97ea0cfeb1b93e33"
    $a17="b1689f3e85811e030024b1ec6e1a1f0e7cf0392fe5b0f1ab3764acb4c30cd242"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}