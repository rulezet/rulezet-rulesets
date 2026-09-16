rule sha512_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="684a5f936b784fe17af79f0054d0dd72b4b6818bee24ac46f3c720c53fa4349525dda61f9cb5287ae7fca4ae4e7f545a68b49748ce8e2fe4e0172a57f27bf4c6"
    $a3="684a5f936b784fe17af79f0054d0dd72b4b6818bee24ac46f3c720c53fa4349525dda61f9cb5287ae7fca4ae4e7f545a68b49748ce8e2fe4e0172a57f27bf4c6"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="a7420f073875fe3e6e2d1af9d4ea90456dbf980f214eb6ef219332e3916f420145eea52233eace5c8df3a2f9aac82d982d5086b6bf62d17000c5c811cc7b4f02"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}