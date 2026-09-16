rule sha3_256_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b22e4b311f68689da4a81cfb0d075ab0eec06aedcc32cbef03ec1fda66401850"
    $a1="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a2="7798f5d064ee771c317e429a5e947ea61afa61a9071c4c0a4abac29ed8a83947"
    $a3="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}