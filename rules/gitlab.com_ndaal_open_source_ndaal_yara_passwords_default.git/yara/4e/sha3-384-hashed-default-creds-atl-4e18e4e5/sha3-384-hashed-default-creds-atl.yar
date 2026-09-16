rule sha3_384_hashed_default_creds_atl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atl."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61ab727033b9407be225f96bff1f008c5d5b1ac43f4db465907819744d2d5ce9d72b0ea26726b1c0d1ded8133f019c88"
    $a1="46fcc10389c81d0e23a943298f68b0590df5d3a9f7bef73261fbf08f3fe76eda697a7f83c645464491549ca852b193cd"
    $a2="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a3="d8d982b13ac9aad8cb3030b3a86aa41e6e673d3fabda25aaf4a1ab184b26ce597fcd7a1e896823d995f25ce18f188150"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}