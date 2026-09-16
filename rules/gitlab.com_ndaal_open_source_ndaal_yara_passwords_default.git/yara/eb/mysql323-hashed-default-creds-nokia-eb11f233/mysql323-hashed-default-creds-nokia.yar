rule mysql323_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73b2e35d17b2d4b3"
    $a1="73b2e35d17b2d4b3"
    $a2="2a551c033eebc604"
    $a3="2a551c033eebc604"
    $a4="51d64c393625fc9a"
    $a5="51d64c393625fc9a"
    $a6="2e782c85379a326e"
    $a7="7a296cc326fc2b04"
    $a8="565497b904012c27"
    $a9="7a296cc326fc2b04"
    $a10="10a781a847b74e82"
    $a11="67457e226a1a15bd"
    $a12="19b522a4743bf12c"
    $a13="67457e226a1a15bd"
    $a14="2e782c85379a326e"
    $a15="21641f392e3dcadd"
    $a16="3d7d6f637a0e2b84"
    $a17="3d7d6f637a0e2b84"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}