rule sha3_384_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b840b1ba3c825da0c4223a4b0dc7bde0494a10d61224cc039630d3b5277daa52a8e57e895312da3db1fc1d7804fb97ac"
    $a1="0ca063dc16aa3e8234bbd5644bd93ceb65324c6cf85b00f711c63505ce5e05adc49c233115a1e153e8ad0947052037ca"
    $a2="b840b1ba3c825da0c4223a4b0dc7bde0494a10d61224cc039630d3b5277daa52a8e57e895312da3db1fc1d7804fb97ac"
    $a3="12e4c0dacec605771b0709aa18a1766858f553bdbe2055050c3005333d117b5affa19debff5b4bd7153f0bb78a459ad9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}