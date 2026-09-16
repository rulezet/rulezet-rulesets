rule sha3_384_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63a2a65b7d53ece73c12a70ff421f6fab0649409b38a637347fcc9748f9258815270bf1f9be9747f26be4f476352602a"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="49f9bc7942e610c6029edb4e99577d184cdefd67be95a5c3f0513e6b2057ce79f0d9b91d1bfd0f9c03f1bb9f39cea00c"
    $a3="0226f5cdea11c457a06b5cf875ebba4ef9a51758d7dd8b78295924b26b686328fb10a15e41526e7edfae7c5aceb2638b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}