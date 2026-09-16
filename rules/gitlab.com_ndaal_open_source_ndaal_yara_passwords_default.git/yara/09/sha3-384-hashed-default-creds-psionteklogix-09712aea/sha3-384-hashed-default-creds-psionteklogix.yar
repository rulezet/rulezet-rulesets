rule sha3_384_hashed_default_creds_psionteklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psionteklogix."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0f74e78e0782ee850f985fb8d2fc4ab5ebb8eab578d59ce41ffa74e614d9e0f4c0d86034130cb48e4c2fec27e07f1f89"
    $a3="562bcb29ac1fea5123ec2070cda76e28495e04f4fb24aee727eff58903d8661541d745bd906260fd72746d22aedb3a2f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}