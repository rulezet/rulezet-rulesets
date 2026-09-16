rule sha3_512_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a1b35a7ed55dea5324acd219a7d97910ea2b3b34312010a9f1f000a213794a1ba2f869bf31d62614442bbbda43c98044396c721445042e587e825c423157198"
    $a1="4a1b35a7ed55dea5324acd219a7d97910ea2b3b34312010a9f1f000a213794a1ba2f869bf31d62614442bbbda43c98044396c721445042e587e825c423157198"
    $a2="2daf88c1bd1aea257668ad4c52c471e6787153cfeed5a78a5e5d9b300c66b016db42da1ea3c69d55a1a02c9089ecd492d249974c70c9051997f47e506613848f"
    $a3="2daf88c1bd1aea257668ad4c52c471e6787153cfeed5a78a5e5d9b300c66b016db42da1ea3c69d55a1a02c9089ecd492d249974c70c9051997f47e506613848f"
    $a4="da7f823046c1dde0ccaf03ee946c36519cf188f764fc0ee8f5fd688791c5ed3474018ed06105f31ff50a265daa71d3bc49bc5ce50afd8c60cb811d13313160d1"
    $a5="da7f823046c1dde0ccaf03ee946c36519cf188f764fc0ee8f5fd688791c5ed3474018ed06105f31ff50a265daa71d3bc49bc5ce50afd8c60cb811d13313160d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}