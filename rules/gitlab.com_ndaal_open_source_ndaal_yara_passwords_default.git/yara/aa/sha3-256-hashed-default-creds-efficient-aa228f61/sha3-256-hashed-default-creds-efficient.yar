rule sha3_256_hashed_default_creds_efficient
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for efficient."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="a2ce5400c881d0469d3fda706ca5392fb9f351ff95a8a300e0fefd11b0bf1d32"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="a2ce5400c881d0469d3fda706ca5392fb9f351ff95a8a300e0fefd11b0bf1d32"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}