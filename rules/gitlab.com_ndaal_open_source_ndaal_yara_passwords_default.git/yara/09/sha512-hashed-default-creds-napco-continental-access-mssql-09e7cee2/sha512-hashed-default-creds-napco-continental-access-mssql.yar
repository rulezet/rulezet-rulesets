rule sha512_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a1="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a2="903557e89325da88e4f8eb3823344eca7985bd290ec3ef1bac564e649e06530cce39b8781d877c9e9f330e114356b05f3e0c51374eb804f0aaebeac069c8a633"
    $a3="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a4="68a4c0f67fc1fb5bd01187b365ffb622602c62afa0b62e8baeceb4f59f69589767952d4644d6e0387cdea13081bc412d39aeccec638b7dfa733ce6ee461701be"
    $a5="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a6="69dd8082e227c91006eefef7dcb1174dd81132ed5f82c5657f853af1e44c230b2e7558b9edecf319c996732b4bc259add125e0f5bcc8077e8e1a3af87d5d9eb1"
    $a7="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a8="903557e89325da88e4f8eb3823344eca7985bd290ec3ef1bac564e649e06530cce39b8781d877c9e9f330e114356b05f3e0c51374eb804f0aaebeac069c8a633"
    $a9="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a10="68a4c0f67fc1fb5bd01187b365ffb622602c62afa0b62e8baeceb4f59f69589767952d4644d6e0387cdea13081bc412d39aeccec638b7dfa733ce6ee461701be"
    $a11="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}