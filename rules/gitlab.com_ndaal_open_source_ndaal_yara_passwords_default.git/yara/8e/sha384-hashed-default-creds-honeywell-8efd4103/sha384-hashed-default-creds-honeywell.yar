rule sha384_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a1="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a2="193762f438590027af3741560adf2059a6580837d22349d802df83135db6afa2e29db6f7e46a9afc72cbee1a38c77261"
    $a3="2848ec31897ffdaed0b78de7c3b840dc47b956bd93b5a2c0a575e688d371974587fe12d8d6a4e9816120e83e95d23a56"
    $a4="334f7e2ce36ab62f4f8901e016d5061c1b3ce42f2a3d87b5d8025d9b81082c40b917bc88f61909964bd880736f391e65"
    $a5="4d252a6764c1e477d9dc97b9d96ec05f08f755b2ce0990025e0c6228281e3f9db8725d6efe4dce28629bb7b85318cd6d"
    $a6="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a7="4477d2e5351a588186edc3371e30f1cfb64ad5f01aac0c504340342e70dafc3343c0b3e878327a8263e11ecf8dd33b30"
    $a8="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
    $a9="032ca822378998d9b1d551df8a4bd8bf7a5d623c8bacc0764e8e9282d66a0f52505ebf640cffa3bd3bb72bb3c74853e5"
    $a10="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}