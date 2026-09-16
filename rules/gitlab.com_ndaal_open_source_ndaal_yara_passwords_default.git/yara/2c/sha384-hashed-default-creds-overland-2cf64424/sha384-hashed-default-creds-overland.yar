rule sha384_hashed_default_creds_overland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for overland."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5889a6a118d1f3968a0216060e6d861eb3b2fa05fc5423674908d92a0c80c335750f12790fa95e03976ab94cdecca47"
    $a1="73114c7a760f92362ccafc80b500ae704167906e9509d6997906df729b4f86e678dc8a9ae7a7f926874920b67b2621e6"
condition:
    ($a0 and $a1)
}