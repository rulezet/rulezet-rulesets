rule sha224_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a1="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="5e8a73b456dfff165cdf5881ccbec3937383695456ee2a5b3a7da461"
    $a5="37f268bf04fe41f664b0d083000291579ff04ff05031ccf960be9d26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}