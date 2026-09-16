rule sha512_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
    $a3="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a4="a16eaa57992dc179b0fd1c8084a6c80a48341b45af5ba1e6b2f5db10ae73ae6a6a9094f7c422560442250d8e4b9901dba0920388f25db6b46faf91554dabe776"
    $a5="df5980b2e1c38bfad3c84ba9a06d367906b9a4f34e6571a1c09d5a3c8f50f7c60f27f29a8d4a87235ea830ccc6845a39cd090d65842827f911650b58f2bf6e65"
    $a6="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
    $a7="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}