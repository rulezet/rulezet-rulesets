rule sha3_512_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f76d1f114cc13d04bfd8e7d325db7d174d512b85cf5a7f798e101cb6779d2dd252fc6d8252d6a19d2a95ace64cf79ed8fc778093932fdd28b53261809c148e6e"
    $a1="0e62aba617f9d3daa94644997e70cbee522ed587f5355df2207aad40bb534c22f6f2126648636bf624ab160132d760fad51b829723c3252bfa112c1d844a6784"
    $a2="5ec73815fe122068a506d57c351bdae988495237ba77b483e2ae01c3df3e78999e9870990b7d99a86906b6cbe2080b1ca5487646bdc70bba185e069f87260dea"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="e7b2497f63ed357c02d08bc5a1bdb2018915d9e7ca47c9b0f4db25b225db569817ee8e4ff4c25ef175fa2248b0184bee172d0c67ce8bfb71b3009260b721f0cb"
    $a5="bf66555bd86ac607e85a1f4d999b998e21a89f7d9320d75e8667303786ab4e82792cb208ab8f30945356cc304b01a5f1aa4ba96015207f4fbd1ee8591cf441bb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}