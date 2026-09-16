rule sha3_512_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a3="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
    $a4="f435ba3ef2bf43e694c8940fa315641c67f152c2ee2021f121af5e03f9860607f74e61e1451f9489c2ff59f87dc0e1c501566e2324355de32770ec52cc3bce47"
    $a5="fb37cebf23b98361f1d8cbb757e3261c0ceb07b6fd80e90a548b62569a81ef9a92eb0e87f7bc5dcd6864a8725622439ead75d3c15d358ea27e10afc30ee4c45a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}