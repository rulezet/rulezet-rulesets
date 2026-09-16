rule sha224_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="42fff29a5bfb53e23cd7dfaafd8ac06275514134502ad9d97388e007"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2a42c5e4eb439512051c7702fe77d5916513550dbf5920d5be088407"
    $a3="42be550a0145ea419da61f3513873d7c976d6d91b53fd85981f496b6"
    $a4="ea0c1ff3ae657c2c79ddebaa6cd411f95394764525c7a3499bea4987"
    $a5="46347396d27b772fad50923e492acb4b8662e03e2cc4affb5e4ef153"
    $a6="335a4dae69567718bdd291d9d684fcda52ef8bf5fe8a8541e0b733df"
    $a7="5a2fbee33fd775ad37848488ad1c332b73f432c907e21095f48a89e6"
    $a8="ee2d93e39d51298022af4b5d1df8a3be22a455beb4bb3e18c539d0bb"
    $a9="f308d01316af4e6b9b0a766f5b328f00723fdc1b97c2859f07bb1114"
    $a10="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
    $a11="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
    $a12="5b55af7c2e964e5db7057da6f10e907aa4befe6d6cf5b19f4b672071"
    $a13="da79ee73928d0b41045809fe692e468aea0f869f025365e6438ad159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}