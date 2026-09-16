rule sha224_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a1="904e1dfdd115698ca60d626134dd92d5f3362df3cd4bcf8fde0501de"
    $a2="7ba5f98ac94c57079d6452cfe6521165cc182a5d25927002a1ad7d99"
    $a3="02f382b76ca1ab7aa06ab03345c7712fd5b971fb0c0f2aef98bac9cd"
    $a4="24289a24be5d6ee8df8f3cedf9b538b4cb69fbaf8abca98797b328ac"
    $a5="6583756055182f816b6c5dba70cabb3be2813c2a57f645ca2f7f79a9"
    $a6="7ba5f98ac94c57079d6452cfe6521165cc182a5d25927002a1ad7d99"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}