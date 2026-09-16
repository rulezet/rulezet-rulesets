rule sha384_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e75984af4914e9531b359fa63ba8abf6b781d6fcbd8698b84d7c3136c5c47e2be33119ed13d064151405cdfeff51ee43"
    $a1="e75984af4914e9531b359fa63ba8abf6b781d6fcbd8698b84d7c3136c5c47e2be33119ed13d064151405cdfeff51ee43"
condition:
    ($a0 and $a1)
}