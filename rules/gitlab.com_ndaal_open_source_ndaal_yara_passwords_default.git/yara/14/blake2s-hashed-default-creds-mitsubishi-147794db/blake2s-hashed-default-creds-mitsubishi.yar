rule blake2s_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="594ce045611b47c6d86239f802c479c17a4f73e78935db061a6419274af5e892"
    $a1="594ce045611b47c6d86239f802c479c17a4f73e78935db061a6419274af5e892"
    $a2="933fbf8af5648c30eff5541ac9a66afa5c44e150b7692545ce361f32246976c9"
    $a3="933fbf8af5648c30eff5541ac9a66afa5c44e150b7692545ce361f32246976c9"
    $a4="a69de6e4ee4b7877991bfb9e6ae7778e852e299050a96c3e32e555f7ef5c135d"
    $a5="ea13726e06548d9258a632f9bf5f062cc58e402db8650030689c2c4c92b46923"
    $a6="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a7="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}