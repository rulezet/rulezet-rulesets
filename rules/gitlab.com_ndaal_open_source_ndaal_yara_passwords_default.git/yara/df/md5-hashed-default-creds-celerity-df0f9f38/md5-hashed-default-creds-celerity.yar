rule md5_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="28e2a175cf1b22e489a88a277b18352a"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="818df59758ab26e0720270b53d728177"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="cc69f666c4058c656acc8817334be55f"
    $a5="cc69f666c4058c656acc8817334be55f"
    $a6="9e57e25848ca617c397b35b6507e2710"
    $a7="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}