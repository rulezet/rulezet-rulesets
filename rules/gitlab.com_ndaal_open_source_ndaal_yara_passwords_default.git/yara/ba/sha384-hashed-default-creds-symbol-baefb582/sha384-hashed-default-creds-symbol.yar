rule sha384_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d25604a8bbfdef1024d3d8c2dbce0f611dc57ff2af88b8a79756eee3254aa3e6699023e69c66a0b3d552cf32bd550b5"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="dacbe2de6441f1b603b49c4f35d998adc878f22108c46c868a49208acb3a22eed93ed8dc3fe5864fc60f232a98aa4472"
    $a3="dacbe2de6441f1b603b49c4f35d998adc878f22108c46c868a49208acb3a22eed93ed8dc3fe5864fc60f232a98aa4472"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}