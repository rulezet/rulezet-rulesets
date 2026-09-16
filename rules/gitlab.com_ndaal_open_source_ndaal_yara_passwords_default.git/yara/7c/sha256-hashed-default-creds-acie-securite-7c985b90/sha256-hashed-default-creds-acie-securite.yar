rule sha256_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
    $a2="b713f0bd8f48dfad2263cabc455ade78f7e4e99a548101f31f935686dff67124"
    $a3="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
    $a4="1c1b3acb877a19945abf4a6d7aef1be60ca834cd599e4b75d5dff774ab4bac17"
    $a5="47b7b77863db62c2eb258b8701d6047f634372ef4ac11ac3f4419529694ff723"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}