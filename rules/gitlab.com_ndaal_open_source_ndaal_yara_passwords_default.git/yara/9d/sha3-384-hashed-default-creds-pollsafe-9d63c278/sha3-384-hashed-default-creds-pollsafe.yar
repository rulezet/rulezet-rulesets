rule sha3_384_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a680be5b6406fe4cd964087f34e5858cd7e892d859118f84e27c4f88321f20e2700e666aa4359b61f74090fa998bfeea"
    $a1="259ef1392fbe43c5db3ee66e3762eb8dc6bd22fe098d270bca99b047c3a46239d3333b8125349b82897d25d587cd2360"
condition:
    ($a0 and $a1)
}