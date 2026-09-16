rule md5_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ed2b5c0139cec8ad2873829dc1117d50"
    $a3="ed2b5c0139cec8ad2873829dc1117d50"
    $a4="cf971ee17d571fc1ffa436a68762c381"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="0ec3772a8336ecddd6b6c61f01c05244"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="ee11cbb19052e40b07aac0ca060c23ee"
    $a9="ee11cbb19052e40b07aac0ca060c23ee"
    $a10="de968fb0eb613d99be01ae7d3d7d3b01"
    $a11="de968fb0eb613d99be01ae7d3d7d3b01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}