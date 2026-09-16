rule sha3_512_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a971232f0db52853a885080b1ef65131f1299e8c6890da053e4a3ad26256bc4881241fa5bd71baa8bfa2d525435dc9ac1aaf90f83d626ae9606db714512baf01"
    $a1="a971232f0db52853a885080b1ef65131f1299e8c6890da053e4a3ad26256bc4881241fa5bd71baa8bfa2d525435dc9ac1aaf90f83d626ae9606db714512baf01"
condition:
    ($a0 and $a1)
}