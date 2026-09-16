rule sha3_256_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a1="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a2="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a3="393eb8dc296a4daa47cba9ea8c01efe16d5ff8bfa2ac8f68bc8c806856a26874"
    $a4="ca2f07eb65e6cef9c0208c127fcbaa96a183c40904b96d2a4ed3be1ab5747e7e"
    $a5="ca2f07eb65e6cef9c0208c127fcbaa96a183c40904b96d2a4ed3be1ab5747e7e"
    $a6="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
    $a7="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}