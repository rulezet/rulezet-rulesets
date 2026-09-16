rule sha3_256_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ca50b06be31750289916ce72dbd7e109be9aec3c1bdc0af80412dc2a468a43c"
    $a1="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a2="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a3="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}