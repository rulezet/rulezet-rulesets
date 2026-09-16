rule sha256_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3deaaf71e54e0692fdde0b26e9ffb7a4ee357f5c7109d582e41d9834d1e0d03b"
    $a1="f877f677d9ec932532789bb16efa289aa29c004bb07bed121dd4de181eb5884b"
    $a2="f1789d72938e61d6c9ab1b1ef994c43bdbff5bfad2639c6ab9542e0b8ed49533"
    $a3="41cac0aae7b9f4aa7610fd2c85382e16f53360625c0797c5f7de9bd1c2bfd590"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}