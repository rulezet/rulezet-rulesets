rule sha1_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12dea96fec20593566ab75692c9949596833adc9"
    $a1="7789b372e834d87529f68aa87b864726bb699c7a"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a5="9f8a2389a20ca0752aa9e95093515517e90e194c"
    $a6="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a7="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a8="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a9="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a10="2cce8164cf94147260010b3b9161413582cca9c3"
    $a11="2cce8164cf94147260010b3b9161413582cca9c3"
    $a12="8eb66215978d93f58b4db7015fb6e981f1866e3f"
    $a13="fea08ffc8d46ad120341a48d38f595d92d6be516"
    $a14="fe594b89f278646cc3ce5992bc884518c113e29e"
    $a15="fe594b89f278646cc3ce5992bc884518c113e29e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}