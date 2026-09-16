rule sha3_224_hashed_default_creds_pbx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pbx."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48594ff9a82c1790a20fda1632a672b5e82d8d3fc8f1966283987d4a"
    $a1="2012e43628843a91e7188cdd08486c8b10768aca107aa7af995974c3"
condition:
    ($a0 and $a1)
}