rule sha384_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
    $a3="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a4="5884c6cbf279b37b558b341666d4fda8fe0e35f649d383e417f8a301e94d0bb50f7c8ae807617e017f78aa84c01f69d9"
    $a5="4c51d7b7b820219e04493fb7c2e59a7443813fb85e9b5cd8ce92ff74bc7a0997bcab1ecba89697e8f469850bbc4d0056"
    $a6="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
    $a7="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}