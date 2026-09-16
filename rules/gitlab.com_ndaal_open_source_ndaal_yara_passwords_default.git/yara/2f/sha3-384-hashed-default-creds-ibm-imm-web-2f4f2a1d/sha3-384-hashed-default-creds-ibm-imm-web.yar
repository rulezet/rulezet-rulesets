rule sha3_384_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c5fe84ed23b8e644aa5982e5b53dff806f3bf2a2c227717e36e3587565b1620593a9717b934d842607df82fb8ece06a3"
    $a1="60ed6bc722a6111382af19977117beb97c865bfccc87cdd9824c86a9d369d14127441c45a064e402166f9341af68276a"
condition:
    ($a0 and $a1)
}