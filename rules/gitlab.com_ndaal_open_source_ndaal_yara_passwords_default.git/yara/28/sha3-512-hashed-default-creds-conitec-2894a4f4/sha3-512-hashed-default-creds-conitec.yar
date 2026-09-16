rule sha3_512_hashed_default_creds_conitec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conitec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afb67f116077ba3cff41083bb7de39420b9200633e9e83d844daeadbc08b8673c6795388d4b4014f236f6220492a08b302ceedec5ed6a33e9285dc181341002c"
    $a1="0ecc5b78ce2a283e7d0a74cad1d9f92b3df9b7512c8b998edcd9cf2f13eeb86ab2e80f6137d9f802f33ed394aa40586b1f899e4291321994e40dc56567c45344"
condition:
    ($a0 and $a1)
}