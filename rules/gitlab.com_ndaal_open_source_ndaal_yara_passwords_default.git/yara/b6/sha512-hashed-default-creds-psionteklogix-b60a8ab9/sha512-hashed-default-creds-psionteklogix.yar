rule sha512_hashed_default_creds_psionteklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psionteklogix."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="cbc80bfdff84ddfa0c5f2ef379f6aae619146a605c221adb2ce518bbd82b54c33422daf3e2a6cccd06eaa5cee4f3527aadfe0a14c2451ae11252d3042bd2420c"
    $a3="a38db1acae90b2f7b58fa438fc027372acda829db34f46688bcc6cdd7546bf7bacc606b1d0f57da99b2f36ed695d5595576e1a54a90b8c33e2840c02c85fc58a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}