rule sha256_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
    $a1="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a2="84da65567426a771c18b2e2294ffa4485eb209e392174bf6737af060414eb7ea"
    $a3="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a4="3b2bcbe6081b7deaccbe0b42f2269a0910e8f2c47ee4e61ccfaa13b3a0de0f9c"
    $a5="4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9"
    $a6="8d3c7a78b824e5a1d6b902d0b63c418c358a4194501882810f4e003a775914d6"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="f0c8303d46ebe569e445b6f65ce43e7f8ba14efef67b36bd2cd6fe97c85e08c2"
    $a9="c2b7d0550420583e8d954747bc3fdedfbf9434a621934aef5f577e5eec2ed2a3"
    $a10="b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}