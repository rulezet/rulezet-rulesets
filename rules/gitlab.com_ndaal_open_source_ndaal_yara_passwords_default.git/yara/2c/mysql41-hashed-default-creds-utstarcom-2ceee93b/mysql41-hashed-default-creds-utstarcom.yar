rule mysql41_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*3E30DAC4E5D90974340DCAEDF28595F68F543BD2"
    $a1="*3E30DAC4E5D90974340DCAEDF28595F68F543BD2"
    $a2="*0218E854E212D4F7A3B799D42F6AA645AD0DFAA9"
    $a3="*9927B7A919E7E5F8DB960CFF2D8E46F6ACA656DA"
    $a4="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a5="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a6="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
    $a7="*A5AEBB616D92AE56DC05FE583CE000F34072E007"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}