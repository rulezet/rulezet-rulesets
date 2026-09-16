rule nthash_hashed_default_creds_mssql_mssql
{
    meta:
        id = "3uzitNi1XTft2ZIugdH54Q"
        fingerprint = "40c8f58db2297a59c512ff9366f35d93710c9ebedd723a77e752ec1593321f07"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8339998d3fd42ab9d3b83cd2d9694c20"
    $a1="8b7f283183bf5eaded3080eac0afea69"
    $a2="8846f7eaee8fb117ad06bdd830b7586c"
    $a3="9cb285c0622b8e5e8181a2b3d1654c17"
    $a4="58a478135a93ac3bf058a5ea0e8fdb71"
    $a5="9cb285c0622b8e5e8181a2b3d1654c17"
    $a6="9cb285c0622b8e5e8181a2b3d1654c17"
    $a7="9cb285c0622b8e5e8181a2b3d1654c17"
    $a8="f799d8e152f7385b34319efe44b0e766"
    $a9="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}