rule sha384_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5e2dd85fe11cec4c913f0f1fcecddb4a654dd92852f978d6345638a0779a5e77ea39d33d6254bde0e1afa7a6c8ef0b9"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="dc06211d2a1e2e97063104b44f9364f4840a8b8b5a772c1daa813d5d30da77b073abed0088af0cea1391b323021e0665"
    $a3="2af0bc8e3f178c8345eb7252abf64cb4e919149716a42bd9de58af74d8b50cff141891c00813ad10e7d55955af7c25d5"
    $a4="e7afe7829b06a9d46a01db517d3e26373ab1bbc337acf89e7f62831d8cd242721f5abbc45ff14cbf63b06ba241668cec"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}