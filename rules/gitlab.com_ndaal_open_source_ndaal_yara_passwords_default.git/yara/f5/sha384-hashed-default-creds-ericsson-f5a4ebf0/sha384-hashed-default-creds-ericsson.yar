rule sha384_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a1="f89feea53b3d49c93be9bba04242fa183701f8dc45a96978254f1afead273efeb73c2acab0fdac339c281731894b2221"
    $a2="42f7113044c011e770740189f408d58fa50b795bd67a83a5dffe7b31a6463841de17df777ecbd9666ebb69e3a5be7d32"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="1e363b70c602295e1f204dadd818dd5f0706b6a5e6a47372f255ed6369a94962396774c254e720b007df320049e1ba9e"
    $a5="a8b4ba4b574d2d02119efe4adecb700911fa1e7a3c9e24b38c5495635a54d7fc92a1391b25caf622e6feb22fd2c1b932"
    $a6="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
    $a7="e261dcccc9be0ef2af5803709466bd985ae371bc9b22fa5aad80f51a80bc627edc259ff738a025e9ac933681667a6529"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}