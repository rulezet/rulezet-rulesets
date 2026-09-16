rule sha3_384_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5587ca6458c64e735493d8d2af1f62ef95dc46584c4ee6120514e996d3b71bad7eb2b3a322fe26c697eb3f3ed7e8d14b"
    $a1="ae2791a1f954f75280b93e43fabfdc0c22169eb4a4f014041bf99be1f6f45c63883c2bfc4c5b00d9d77d9e343cbcdc91"
    $a2="5587ca6458c64e735493d8d2af1f62ef95dc46584c4ee6120514e996d3b71bad7eb2b3a322fe26c697eb3f3ed7e8d14b"
    $a3="1aea2a317b8ba3bc432ad63c4896c06ed6560e171d83aec1a548bc2ba34009d48021474c3258535e52fb2c266af2940a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}