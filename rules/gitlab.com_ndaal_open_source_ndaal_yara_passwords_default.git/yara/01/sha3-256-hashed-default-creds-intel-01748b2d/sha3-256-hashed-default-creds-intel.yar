rule sha3_256_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a1="639fc370f71c08ba6077574a8239dab4aafdf0583852320b944cc75b9cbbb944"
    $a2="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a3="ee94029bafba2122214a9d310dbea3b88153e18c03e74ea9ace80fa66f20f38b"
    $a4="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a5="75bd51a194f52e0f8f26344c29821b4ba21488db601f06111ea67258c9dc9535"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="46b8aa14f3a5fe5aee4be26c5e33903e1c67df5a8bb35fec5332f8585b2eb6a7"
    $a9="dd51340386dced8be57309ebdd0a92fae5ad55e1013bca1d19d3e210230229d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}