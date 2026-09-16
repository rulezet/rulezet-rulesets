rule sha384_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bda90c54524168b4df84d1dd8008f3994987bd136fb8ab26a17c677a8255585678415d95e5e6c3608701d6cae67fe6ae"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="4f741e737e89ff8f6c806ddc61ad9b15ad67702e2329f6ed92d51c6b12223a81b31f97841c6ce6fb22d8c99d68c07815"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a5="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a6="3aa4921f19834b4b445cad30e6a760ad7998f195e34b16690b74e7b31b8da1e543cd23ee01c33b2b8b907de63b086385"
    $a7="85e2993e1713ef21cb42470c22bebdda1cfdf29a48cd8ef1edc8b9651f7ef7b181c260db565f12e07a6200f8a5992025"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}