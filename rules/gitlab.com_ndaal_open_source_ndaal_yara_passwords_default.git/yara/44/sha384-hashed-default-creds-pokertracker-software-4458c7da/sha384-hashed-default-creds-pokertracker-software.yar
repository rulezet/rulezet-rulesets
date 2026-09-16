rule sha384_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4dc8a5cf162cb741950819283217c3f9fd667c87b964783363e760f3944e62c1e7c7969da79361a0e5d34a880619e8b0"
    $a1="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
    $a2="9dace96ea60eaf0a2aa29136f63c9e6dcc40a11e38c02d0ac82ca3f15a96f289c39a33a44db3a298ee888112431094b3"
    $a3="38714156df7b6d05ad026f0fde653e7744526e1090ad2c7dd22cc8a504720fc064a2704ab17f8162d03ee8482767115b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}