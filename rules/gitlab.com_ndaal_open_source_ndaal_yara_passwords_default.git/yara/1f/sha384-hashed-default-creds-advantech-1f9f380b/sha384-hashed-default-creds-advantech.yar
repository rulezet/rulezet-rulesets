rule sha384_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="279ccc67a91613e7e0fa3164543a3ceef9c93e33fa3eaddc0d408fe4e6002caeee32566a517bf4380adcb0cd21f676c4"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a7="cdb347a3e6fd5b295b638951e19d0908625c711942c8eeb09392a027875369b2247940668af06bcd74d5761c69b057c6"
    $a8="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a9="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a10="594f577a573d9517133e09ed29eeb0cbed14ea1b36bd060d13501caa03f0bb2049e6a06b9c919d007afc8e44064d6217"
    $a11="04b222c4ef00cc3fd8454ca1c212782c850da027609a4ad5633e6de52112e0d73299eb8d7357a376a8bc05035326b238"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}