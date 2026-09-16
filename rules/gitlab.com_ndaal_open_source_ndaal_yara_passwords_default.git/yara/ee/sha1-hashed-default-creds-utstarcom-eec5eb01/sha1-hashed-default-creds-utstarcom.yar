rule sha1_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d3c4f83bcf53415e44694106b5b00ff62a2dea62"
    $a1="d3c4f83bcf53415e44694106b5b00ff62a2dea62"
    $a2="8fd45370cdd18ea297298716d6cffb048ee662b4"
    $a3="a1872e333d0e52644f6125da2276530f7ebe5e77"
    $a4="2da0b68df8841752bb747a76780679bcd87c6215"
    $a5="2da0b68df8841752bb747a76780679bcd87c6215"
    $a6="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
    $a7="c85824757a373c98d17b56b4ea9a5649c5bcb55f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}