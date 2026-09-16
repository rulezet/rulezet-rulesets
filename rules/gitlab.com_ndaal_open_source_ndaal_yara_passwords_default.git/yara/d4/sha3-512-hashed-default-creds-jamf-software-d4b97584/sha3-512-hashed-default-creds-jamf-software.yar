rule sha3_512_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7971dd2752caf9dead4a023ce9b9773225f958b1c36ba8ce0e13ea59fd0d32a008daf9bdc2ffc5ae57815f832afd2c2388f54adb3781ac1289fd0ed361efd2aa"
    $a1="572420a19fa2fd8467d2fc1f1f8b3b4bc7378597816867367b0dfaca7e92ee58e34a4e58bdf56a984d4f4bd8da5311783950bfc372ff30af001e955f0e31f2bb"
condition:
    ($a0 and $a1)
}