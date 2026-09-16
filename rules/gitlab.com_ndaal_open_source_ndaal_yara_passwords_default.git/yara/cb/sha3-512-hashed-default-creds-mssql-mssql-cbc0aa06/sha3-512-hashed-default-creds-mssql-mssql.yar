rule sha3_512_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81b9a4c4774e36ea76916431f85dd466081d6d6049e84047076923ae8e42e3688516f8bca0ba8931e0e8a9a720cd41849e033158c34d272863d9e76cd0b1fdc2"
    $a1="50e617641431d65dc867f4b8501566a518e3a55115e0aa2772aa34f39445a75114eec29e00f8870dd2d65bcc9ad9c3fd735257a4cde89906c30d30666e5e48a3"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a4="bcc03f9763a44e3f3123441603395c2267c019f44d1a82e2915416804c9f8889ed2b543404ae4c6d22b7b8bf829ab8c60b02c593058191d274e5425234e7d5cc"
    $a5="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a6="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a7="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a8="6dae4955f1d61bc13e9a7c91f05c295586996748f09f01971ba011af4e5c3d26d5e7bcf9645dc4773b09faf679b8b90afc5fc85b6b7436d6f5dc82ffc01da7c9"
    $a9="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}