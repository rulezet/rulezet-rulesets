rule sha3_512_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="987e939fa2bbac745e66672525d4afa672de58df204febb20ce61060336b89254403fd8692bd26ef4974875e3a0102ccbd9fe7032f7560adedcfd70ae6ec957b"
    $a1="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
    $a2="c935abae9e50c4fafe2c3f40ed6478696344694e797a0283bb97cf275b4c7ccd02d87a7473e383e9c726beb28fdad65b288c0cef81c3b4f925558e17316e1745"
    $a3="6f2f120c48e33f1ee898bf41032c517553e237cfa790f820ba68212a06c450cd7fe8dd893d1bafe678ddded66baee00788b9561c174fa063df304d92a85c5234"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}