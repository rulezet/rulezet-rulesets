rule sha3_384_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="526de9759ee8f505bb0012bd754f1c75a1948c972269153f2fedbf6c8238cf24f003d6cfbef8122da44bfa2d4bc541ca"
    $a1="526de9759ee8f505bb0012bd754f1c75a1948c972269153f2fedbf6c8238cf24f003d6cfbef8122da44bfa2d4bc541ca"
    $a2="6481bff91752a75350c7418779dcea20b705ffec22de4b3f5ea3926dd693f6128066a1aab34a0f636fbf2aa6135212d2"
    $a3="6481bff91752a75350c7418779dcea20b705ffec22de4b3f5ea3926dd693f6128066a1aab34a0f636fbf2aa6135212d2"
    $a4="91bc1fafc4c7e84200a31f696b046f3bed8d5c56667840f45f2ec38bf57094537656d12a7d75b31803086a799ddd7e75"
    $a5="91bc1fafc4c7e84200a31f696b046f3bed8d5c56667840f45f2ec38bf57094537656d12a7d75b31803086a799ddd7e75"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}