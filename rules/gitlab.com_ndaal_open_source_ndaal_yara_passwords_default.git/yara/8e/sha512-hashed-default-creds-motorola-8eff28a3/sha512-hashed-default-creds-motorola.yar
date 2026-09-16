rule sha512_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8391976da1e82092fa39893979d25f9714e39ef9367ecd90b15eefb8b7b80540e7efc91ad74abe135d0e7eaaeebdec1e126e840471b2ba692e04447ee85366da"
    $a1="baaa60c571adfc75b00432283b6fc4293dbd366f4b1f031e85f32251b4298b25fc49c74791014b158193b3c2f5de52077d5fe94e5a0820165b2330e63cd9ce15"
    $a2="2aa271963bb68c9bf0b44736814a288bfccc0a5d1802e1ee2c2b653158faef9e6d66e9f805c8fca303d4d82d97e2b5d613f792410b2ed50c044a0768398b991f"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="8309dd7c52675caaf669868c10bb5616d28daec1e47001277118e7832a22fa7e624a497edcae4a8eb0c74b9f2f64882ce7978492b99cc4975fccece756c4712c"
    $a7="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a8="be460ecd19614bd7d5a1e127a0d9e717128c5472b4555017f8f053a9c1856d5c1816d69b3e061e25d7045e7c00b2473b75418cfdd4e919253d3c7a37721f6984"
    $a9="1008aee4cee1463834b3eaf369b8e6788f456bf39d1cebf505697ec8701b685e95b37d2e05d8ee2742bef77debc7af52111b339f926871ff33bd3ec2c314d9bc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}