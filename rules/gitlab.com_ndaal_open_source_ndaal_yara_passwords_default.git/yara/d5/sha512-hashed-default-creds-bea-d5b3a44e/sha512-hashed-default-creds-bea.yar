rule sha512_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="226c72af6fd3dc3ba3c50d56b43dc79cc93482c57a1359089cd6cbf5a3e5095d0bb435609df2290bf126295dab0d8e1fb45409a348bb223eab5f29622f012b95"
    $a2="f2a46a9101d3b65c419c98a9ffe73c154196bc3e87379491746cf5a70ee0b5e4d308b27b28f77960582d8ff88ab7c3c4930860436bf05d6d5517c8e3f9efb8e5"
    $a3="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a4="5af950b6531642271d1fd9f9c52d40b631cc64917067c599c0387e6b5f4542f99cb9f5fd1d2ab5446c4c309021700d36cb72948fa73615f63eb73354d398b6f7"
    $a5="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}