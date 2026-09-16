rule sha384_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0831bfb59eb75eca8d74ed393b18044884d7b1acd54369255496570027d7fa4f8818fc888d191f2f3fd198ddfa5d45e5"
    $a1="392b0f28a6b7827967a93a52306347a74c51f2db12c582546008c7a3dfcc3b9d11c49b0bd7ceae864be4e55020b336b1"
    $a2="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="e063d31a6d256a31b2d1882a9cfc0ec4de630d4af37b6e8942a5cb1bd18b2af08fc937e773564b559161b670301d9114"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
    $a7="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}