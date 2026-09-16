rule sha256_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    $a3="e07451d956a297e8e76d83b519ba07d48bdb19cbe04cb54afd276bef632f55c7"
    $a4="3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    $a5="e51783b4d7688ffba51a35d8c9f04041606c0d6fb00bb306fba0f2dcb7e1f890"
    $a6="18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4"
    $a7="67e1f11f554b39f1f6541d7b74439a90974ee4001a507f44737183249d5cd4cf"
    $a8="acac86c0e609ca906f632b0e2dacccb2b77d22b0621f20ebece1a4835b93f6f0"
    $a9="3be6c7a374d102bc596007c668ace05a8295a0ad7b86ed7679302be57e53b936"
    $a10="62c66a7a5dd70c3146618063c344e531e6d4b59e379808443ce962b3abd63c5a"
    $a11="8d5c39b54bc9862ba36bc6488b27e67a42a7f74ef59a91e866da9d27540f7216"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}