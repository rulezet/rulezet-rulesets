rule sha3_256_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="5a9cb4b1795fdc8982e907994a2e80eca49b6daf329c826d86903016391506ce"
    $a3="5a9cb4b1795fdc8982e907994a2e80eca49b6daf329c826d86903016391506ce"
    $a4="d614fea114454c8b39c7753dd94649c648c6fc0ae67db22adaed1069a50b0f9f"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="6c22ab290fa2cfb02c5b3b87f60cc8f3ab5bc1cfe37f4aea904d89b847f90342"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a9="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a10="9dd244510bfb39ac4a8be358c60e50ea60481934dc77badae9a6f5fb4bba56fe"
    $a11="9dd244510bfb39ac4a8be358c60e50ea60481934dc77badae9a6f5fb4bba56fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}