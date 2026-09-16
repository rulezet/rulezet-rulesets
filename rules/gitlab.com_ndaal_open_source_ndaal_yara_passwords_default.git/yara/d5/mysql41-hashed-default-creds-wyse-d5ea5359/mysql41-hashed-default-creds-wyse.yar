rule mysql41_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*564CD623B2DE65EE668E6AA20C7E92AB904A55DA"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*E7E9C7889AC83D022AD5E75BD4EB273581BE15F2"
    $a3="*0FE12DD55BF55F6C706D5B534BA05A8E88D41429"
    $a4="*6C6FDC5F8A65C193DCAC5E9C55383E33A0166776"
    $a5="*F3BCFC877EBD13E3D29A07D4F13DC8B3BFB461D5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}