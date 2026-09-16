rule sha3_384_hashed_default_creds_seclore
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seclore."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0abe854ffc0d429c5d5dfbf6acaef489bd61f538e518bd2540c1ed4cef8e3e46c8a80c91c3f1ad9418a826e7859655a1"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="0abe854ffc0d429c5d5dfbf6acaef489bd61f538e518bd2540c1ed4cef8e3e46c8a80c91c3f1ad9418a826e7859655a1"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}