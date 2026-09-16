rule sha3_512_hashed_default_creds_titbas
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for titbas."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d08426b06b925f20460c8a7983a3e7f4528c842e7d8a1eeaecf869e0271ed6371b5e9ed09070ec6f9ac1d87b3903576a8b3f69e6ea66fa50773486e7581babb"
    $a1="04a95d14009ea231eb4653afe74bf8d1d60520c8793c42233befcbaabc8251358f167e8782fd0cc28c9441b70382b4b3b652152ea505849faac2f145ded71c7c"
condition:
    ($a0 and $a1)
}