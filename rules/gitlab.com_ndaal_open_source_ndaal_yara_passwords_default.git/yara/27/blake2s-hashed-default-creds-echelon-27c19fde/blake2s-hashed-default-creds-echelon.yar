rule blake2s_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
    $a1="5756d18256a7d25364cc470f20e1d507b17ed879fad7fe484b9140cd8f4034a6"
    $a2="89327b6fe3ff58072b91e5db974033aa1d3a045a49393c3b615a43cec28cb9d7"
    $a3="eccb5cd52034303a3c88c8e59400bee1391b26346e0774238eee2796c469f3fc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}