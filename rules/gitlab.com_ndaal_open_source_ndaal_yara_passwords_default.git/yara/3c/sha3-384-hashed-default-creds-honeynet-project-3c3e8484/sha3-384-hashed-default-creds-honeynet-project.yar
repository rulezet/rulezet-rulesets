rule sha3_384_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
    $a1="f061a66a80ddebc82e99efb271aa6ada1d75460fc82aa9457baee6c612f33aaaf06cc5dcd79dc5100043916ae4eaad29"
    $a2="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}