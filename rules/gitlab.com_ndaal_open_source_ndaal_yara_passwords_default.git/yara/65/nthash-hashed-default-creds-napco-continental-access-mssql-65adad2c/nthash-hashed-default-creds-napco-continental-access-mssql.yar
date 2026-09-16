rule nthash_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        id = "v0nt41vqyL3KafyFXIg2I"
        fingerprint = "e221ccb89738948f9ba2529ad122f0f634d11d670d7c40aad0e15a9b508709ce"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5c30aba9a200e487dddc9a00b134031"
    $a1="b5c30aba9a200e487dddc9a00b134031"
    $a2="93fbb3f777552ca8f66945daa0bcab50"
    $a3="b5c30aba9a200e487dddc9a00b134031"
    $a4="cde8b750965f6fb65986e527ca350258"
    $a5="b5c30aba9a200e487dddc9a00b134031"
    $a6="b5c30aba9a200e487dddc9a00b134031"
    $a7="9cb285c0622b8e5e8181a2b3d1654c17"
    $a8="93fbb3f777552ca8f66945daa0bcab50"
    $a9="9cb285c0622b8e5e8181a2b3d1654c17"
    $a10="cde8b750965f6fb65986e527ca350258"
    $a11="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}