rule sha3_512_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23ec62c75dcb6d11ed28236cad8ed6fa83081d378fca9c7cb1ca0dc0370960f1f40f00fbde61c89ffeb56d3b912be45246199613989eb5e9f77172ec58870d63"
    $a1="f7e0699f92fb0453618922b080c55e79a5d8ec453eb787ba2c573ccfe6bbfc329cf67e384f43dc73a469bd336f26e55d1634b98ac9253653b86e6148a2ff273f"
condition:
    ($a0 and $a1)
}