rule blake2b_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="beb79815dac210945116b7a33b33521f8981f6f615fc72865d8a51dd7a5711f9a8c895a8d849b3265b6e9cdffce2cbdfa9cc88fe89a7a5ba923a84718ea3f14f"
    $a1="beb79815dac210945116b7a33b33521f8981f6f615fc72865d8a51dd7a5711f9a8c895a8d849b3265b6e9cdffce2cbdfa9cc88fe89a7a5ba923a84718ea3f14f"
condition:
    ($a0 and $a1)
}