rule sha3_384_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
    $a1="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
    $a2="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
    $a3="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}