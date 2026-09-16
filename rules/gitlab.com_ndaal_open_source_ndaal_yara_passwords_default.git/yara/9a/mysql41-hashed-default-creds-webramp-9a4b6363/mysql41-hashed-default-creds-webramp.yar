rule mysql41_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*CD809450EB304C11D7D2FE01AE4385BCD3386F70"
    $a1="*B25A8734335D2A61C756022889434327771F0299"
    $a2="*344C7C92E4C56FD1240390C67BC3082FBC3A2D71"
    $a3="*B25A8734335D2A61C756022889434327771F0299"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}