rule sha512_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="c884a2849503efabb12c984ba4ffaed6a99ba3b24cfc647b63d4f4194a20373f10aa31d9571df9fe56a40fc49548a5033471ad5123b68bf6b2aaf53c125af4a9"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="c884a2849503efabb12c984ba4ffaed6a99ba3b24cfc647b63d4f4194a20373f10aa31d9571df9fe56a40fc49548a5033471ad5123b68bf6b2aaf53c125af4a9"
    $a5="ef05b6eae39eb51b5b8ca1c3ccc85ec4975fffe99ae816d1f8f78eb25bbc3eafc0de8fb8589a9f92cea310d5703df0e4ce5cb20ee51df40c1a1f5caadac1ffb3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}