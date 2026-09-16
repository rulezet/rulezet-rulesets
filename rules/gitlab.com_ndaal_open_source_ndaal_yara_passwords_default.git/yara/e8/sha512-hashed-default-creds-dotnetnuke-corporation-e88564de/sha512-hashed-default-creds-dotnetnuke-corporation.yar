rule sha512_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f45c729468e5fe1656e8e74422b147596997cc93b2d0c1acab378c45b09cc2fb6c4aec9747abdd0adae32b0a73e4f336844e85a88ff07bc4db47756215a57a71"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="f7f521459599be132ab6b8398cc7992441496e525063f6094cc0d0aadb283cb5ede95bf26758acc6a8c4868c20fd53b97c3c2ce6e21459eaa3be0f7d234ffc3e"
    $a3="274a91d963475a541cb072db6e7009f74a90382830c61f522d1a3b04830852c134ee445a9a7c6edabd54c55f4b702e876891502af9bcf4a09bd0fb1686f17f75"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}