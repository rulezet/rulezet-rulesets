rule blake2b_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
    $a1="da8d291e0916119783bb03757c6252fb55ea1d51bfb05e3044d676a827ad9afd002fcfdc5706406cb66b61cea06b9ba64f895d7e66b8aedd5bd84182b9b46fe0"
    $a2="6bb66cde640f884e21f94de7c15b66bdef76193b1a59238d786dccc661ff2f172d177809cb8b5991299bbaa9ad1fb841d5c7a71945581697dd6020330ba4a49e"
    $a3="6bb66cde640f884e21f94de7c15b66bdef76193b1a59238d786dccc661ff2f172d177809cb8b5991299bbaa9ad1fb841d5c7a71945581697dd6020330ba4a49e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}