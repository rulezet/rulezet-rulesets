rule sha3_256_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a1="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a2="6e9d54d7ebe3029abf15866b51294ce3defb2bc2c27762570819f0959b250499"
    $a3="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a4="ff5be1154d3a9d628b4c62b2b13d1dae5bfe66d2876b297bced9b6e377219a27"
    $a5="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a6="6e47a3ed3b57b60dc109bbbb43e29626d3f695dee5aee9967f002fdfa44a41ff"
    $a7="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a8="e8b886c9f9d7653d27a953cd2867adfe43db18cb9c4cac21d15086dc294dd450"
    $a9="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a10="37b0edec323a7fc924dec259de1b1c59164e2ede27fd51e830dbd6bde7d00839"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}