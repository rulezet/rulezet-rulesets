rule sha384_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="d1e417c541712287a7ab93ec354f0146d8312ee6378b38f92147cca61c2ed0bab1ce98541c1fa52fd9f2e25bdf89a1c8"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="d1e417c541712287a7ab93ec354f0146d8312ee6378b38f92147cca61c2ed0bab1ce98541c1fa52fd9f2e25bdf89a1c8"
    $a5="5493a250d3ff9a2a54132a51ec6ab26d32b8b08da3763a1c94045602e2c2acbb14a8d0a4de99ca04645fc5f2a4ff56dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}