rule sha256_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d4c7328a3f7407c636b2ccb97830294c162147f814d96af2de0b1c84e95eb77"
    $a1="9d4c7328a3f7407c636b2ccb97830294c162147f814d96af2de0b1c84e95eb77"
    $a2="a1f259c43f119e8b79115828a9c87f4c5a31b412f52befeef0f2067c70ead090"
    $a3="a1f259c43f119e8b79115828a9c87f4c5a31b412f52befeef0f2067c70ead090"
    $a4="ca3e729584e18937efe6fac042de759769e4c1459c5b685d62c29567d58b00df"
    $a5="671216546648d8d608fd0e62a36b30801e8ce6406fb2b41bed3c20dcd553f671"
    $a6="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a7="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}