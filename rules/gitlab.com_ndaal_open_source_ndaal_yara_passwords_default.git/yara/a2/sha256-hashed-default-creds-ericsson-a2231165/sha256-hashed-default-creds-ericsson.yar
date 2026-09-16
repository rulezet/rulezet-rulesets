rule sha256_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a1="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a2="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7"
    $a5="2afbb1b55c6a2417ea3a1294bb7436009df69b1c112a6d06d381bda807ee05ff"
    $a6="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
    $a7="c7d253870ab8de3825e3a9b5ee603e21abd0dfe62763e8e2fc1fc9f4684e8a19"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}