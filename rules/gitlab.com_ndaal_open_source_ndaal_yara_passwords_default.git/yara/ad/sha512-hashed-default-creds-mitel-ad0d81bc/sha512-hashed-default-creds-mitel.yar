rule sha512_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a2="1227de669e122a546edf39f0ded50cd2b6332793dc55d835b21be05bd529511655877292748c25f8fc2b5f1d5c987d9aaed2fc92c7e59a448e51cdf1dc5351a3"
    $a3="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a4="f33cbc9e2655d55772043dcaa15d9a5fb813d80af5fa4a5ea606d48cb847f23d73e8cb90b88a0781d3e9fc84ed4aca57267c07ec94f053bf5553c05ebbc01e88"
    $a5="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a6="7786d75d8aab53ddcb1a6e4ce1355f77f6014457d200f39b1770d2b6df5aa5780cf94897bcf645a39324feb9bc7e4093e3bced058b2e180eb4794d5192d7f07b"
    $a7="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a8="9ebaed300bc94f411d9ca29a1978854c4d3e756cac711984feab247c471244d48d87352a7a1d0759040a02134a5673eb34294279c32078042838ec1170dcbb7c"
    $a9="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a10="4cf5a5be41f417cb2087f1f17e44734ae9b1677dc6b0ed3b80de422cc8e5607980ed08334540c15966485db039927bade22d3dedd5fd3b3f7d9743c20310882c"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}