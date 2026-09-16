rule sha3_224_hashed_default_creds_sierra_wireless
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a1="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a2="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a3="78ea025335170e402f29f1e3f581b3ca4dfe9bdb8a381ba7c630a299"
    $a4="94cc697550f5c7399d179e206cf1e7bf90e17de8a87ff0f9368ec839"
    $a5="83c9402b8e461510b86ffd845654ba69548e14b68cef6bb483821944"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}