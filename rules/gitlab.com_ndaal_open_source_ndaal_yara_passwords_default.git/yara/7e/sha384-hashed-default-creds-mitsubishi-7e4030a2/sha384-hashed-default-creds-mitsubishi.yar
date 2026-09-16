rule sha384_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="52da9ff22f2d5627823bd3de3fe8f677e16f808b5612f0e88a9d206de993922d3b15f221c4102d00b5c6d0ebfce4a461"
    $a1="52da9ff22f2d5627823bd3de3fe8f677e16f808b5612f0e88a9d206de993922d3b15f221c4102d00b5c6d0ebfce4a461"
    $a2="254e62dc74ddded1747bca9d68dbb7664de3b9fb88a7096ede7a02aa53c0fe5531f29441bf5e758f79a14a74b04c4581"
    $a3="254e62dc74ddded1747bca9d68dbb7664de3b9fb88a7096ede7a02aa53c0fe5531f29441bf5e758f79a14a74b04c4581"
    $a4="41f45635576e8bed250f7412563d51e834c0da9db0ac84e2e166be8a0398a7875af322a958b8b24824b29e93441b3c73"
    $a5="d5171f7932a127282a9d3c947e66c0cf983a471a987e9eb2891eaf55fd39816ee893bf2a29eeaf8d940627a6085b0f06"
    $a6="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a7="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}