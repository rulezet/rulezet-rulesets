rule sha3_256_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="118d62788fcddd499bc489d5b336964984a7485b86bb01d6c85744806a3f774a"
    $a1="118d62788fcddd499bc489d5b336964984a7485b86bb01d6c85744806a3f774a"
    $a2="c938ec247e796d99a07cd0194378b84b8e278738db327869d727c410d03dc603"
    $a3="c938ec247e796d99a07cd0194378b84b8e278738db327869d727c410d03dc603"
    $a4="1253fad7b73d72305c0671b459069d5d7650fa54aad3d6dc3071a75a1a2bd079"
    $a5="a93c785803401e328d1936421418fe9145a12120136490247f878e26c7afe1af"
    $a6="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a7="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}