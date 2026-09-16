rule sha512_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc47b055fbdeb77058fd58922e1393393b47ae884401e7203b235d8751bc6ebd25f2418501356e5a9f8d9033d185ce1f1b891eaf73626ad3a707b364266d658e"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="988de5b4640eab1c331a8c123ef133fc427652df04fb1981c4fdf48095951e15b6682776f62ba56e32e82ea4ad0171ad0cc6a34bae7bfbd45e47b60435932af4"
    $a3="91f325261bca90f05e2175299e9fee045003017047114b3662b79201d05342edc72d4f5ba805ac9961f2f43c66234b5070e9d4c67dd324198afb00eee4c916ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}