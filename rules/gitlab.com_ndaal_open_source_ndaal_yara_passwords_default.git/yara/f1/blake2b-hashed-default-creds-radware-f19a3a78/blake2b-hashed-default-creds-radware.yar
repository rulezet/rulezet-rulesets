rule blake2b_hashed_default_creds_radware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radware."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
    $a1="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
    $a2="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
    $a3="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}