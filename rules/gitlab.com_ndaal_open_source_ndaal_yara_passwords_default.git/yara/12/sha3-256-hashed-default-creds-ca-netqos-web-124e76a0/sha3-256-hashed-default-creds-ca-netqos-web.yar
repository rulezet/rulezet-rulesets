rule sha3_256_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10fc63c92fe1228ac86cb575da83dab26fd66b70b98a9d12284d22bcbbda796b"
    $a1="4041d8aad7dc3e88a67358053cda689eca3562ed1fcacc7d367284f61170f87c"
    $a2="10fc63c92fe1228ac86cb575da83dab26fd66b70b98a9d12284d22bcbbda796b"
    $a3="5fb62909fca27fd55bde18f90056ce92da9a82b204ef11d36abf15b72d40f5b0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}