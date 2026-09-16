rule sha3_256_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a1="7798f5d064ee771c317e429a5e947ea61afa61a9071c4c0a4abac29ed8a83947"
    $a2="64e0033a157085ecc01bc7e53e9f6e032754676e57788f5b92bd147efbdc4a2f"
    $a3="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
    $a4="1037f1f67277cd916301c10e5417b95c117abbd8daf2b794c30a90ee67898b53"
    $a5="a2ce5400c881d0469d3fda706ca5392fb9f351ff95a8a300e0fefd11b0bf1d32"
    $a6="64e0033a157085ecc01bc7e53e9f6e032754676e57788f5b92bd147efbdc4a2f"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}