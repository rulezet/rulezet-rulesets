rule nthash_hashed_default_creds_microsoft
{
    meta:
        id = "66tdNWD9yvpfloP1Nbor8k"
        fingerprint = "664071a91bb4e506c5dd9856b40bf6d809b026b5e87e3867a0db31df798ba7cd"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="57d583aa46d571502aad4bb7aea09c70"
    $a1="c88c185ef8deec9b9c846743be92bd68"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0280777f37d4f4e7c478d21cec701463"
    $a5="0280777f37d4f4e7c478d21cec701463"
    $a6="d144986c6122b1b1654ba39932465528"
    $a7="d144986c6122b1b1654ba39932465528"
    $a8="3d2b4dfac512b7ef6188248b8e113cb9"
    $a9="3d2b4dfac512b7ef6188248b8e113cb9"
    $a10="0af2b9053748dca06c597f4b2573f9f3"
    $a11="0af2b9053748dca06c597f4b2573f9f3"
    $a12="962e17f6e8204b0586fa10e2df266f60"
    $a13="0b949d4edf5126e318fb50a92e8f6ce7"
    $a14="79e7bfe8a33cb4c2ea6c83541aeffc3b"
    $a15="79e7bfe8a33cb4c2ea6c83541aeffc3b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}