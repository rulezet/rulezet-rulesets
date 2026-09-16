rule sha384_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6593a396145ab27507c46a3fa04de5260498c394c48b7eceb17c46c9261f7297c22c28a33d67dfd98736d04a62bbfbe9"
    $a1="09385519474aee53a42e2d7191474ed4b0808b7397544e7de03592c51e91944f288e0329f3ff371c5712bc422e60357b"
    $a2="3f75aa9266c066b106318aeb0301226ebba5399d4da3c9e5264e2f7b2f06ecc16653de49816b7f767b41dd138336f613"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="bd30a1fc0c93c29e79c60b2e84abf991d6d9f398e78800cb101164f6510fddd79931b2efd29593a453f8bd47a3df7fac"
    $a5="7ff7cb97b2e4e787f7129e88a56ddecb5eb23865ca95839498412faa533a545916f8053a8ea0523aa3ee9daf99013f4a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}