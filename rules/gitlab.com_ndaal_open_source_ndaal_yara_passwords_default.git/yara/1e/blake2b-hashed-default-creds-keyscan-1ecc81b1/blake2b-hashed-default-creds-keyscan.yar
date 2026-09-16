rule blake2b_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="396f6050de5cdf7c3d4bbcb66a5b668d21b5f77c028fbb2fee1d537330632d0be8b6019d91adad6438083b2f6ffaf580fd82869c4ea19eadfe016fe0d871d025"
    $a1="a0034d1c7efcdc5add18c9cc1fab87d63ccf579468b9d778963248c38b6c751bc16de015298927e9ed8354a894a414709166009c1743eabab59dd3c1aee0a769"
condition:
    ($a0 and $a1)
}