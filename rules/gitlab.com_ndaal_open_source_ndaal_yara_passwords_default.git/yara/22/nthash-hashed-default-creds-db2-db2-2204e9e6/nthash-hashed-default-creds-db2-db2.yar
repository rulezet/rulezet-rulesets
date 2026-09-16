rule nthash_hashed_default_creds_db2_db2
{
    meta:
        id = "7jthgctlOlJG3WKwkP0EYw"
        fingerprint = "bb0705e40f307a6426af52f224f0da871b816338292abfcaafe613aa081765b6"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8339998d3fd42ab9d3b83cd2d9694c20"
    $a1="715f327b7f9b07fc64f4b54b510cf486"
    $a2="5f620af16778d6b66630094296bb180e"
    $a3="5f620af16778d6b66630094296bb180e"
    $a4="6c2ef9cfa81c71cbbd0b770e1e588017"
    $a5="6c2ef9cfa81c71cbbd0b770e1e588017"
    $a6="a951eba3f209beb362bf5f03ee8f51bd"
    $a7="a951eba3f209beb362bf5f03ee8f51bd"
    $a8="c7d8911da2e4a4f49f91a25914c56f00"
    $a9="c7d8911da2e4a4f49f91a25914c56f00"
    $a10="baf03cbdc0e7e9404c60100fcba5d596"
    $a11="c7d8911da2e4a4f49f91a25914c56f00"
    $a12="92f6e0e5560642f395ddc82311d32aff"
    $a13="c7d8911da2e4a4f49f91a25914c56f00"
    $a14="a8093ebb8f417d5866b0a1fa2bef06c0"
    $a15="c7d8911da2e4a4f49f91a25914c56f00"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}