rule sha384_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
    $a1="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a2="1896d30c608e95c321b2cffd60ac2b71b0662b94e55a70b3d0c53f0a62cdb9698969a372311ce51f0d278607261d2e52"
    $a3="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a4="db0a91119745c6bcdcf60558d29bce5594891bf7da3ebc8b59f02f1cef2a4598adbea5345be0cec7f4934163df2616ed"
    $a5="4cfb880e9b3d538c7671cb5de2f6523956d42f011838486320897688aee9c49724207bd39e04d9b74d67ea8dd30ec3c1"
    $a6="f6dbb4d5687a9ea5fe44f4c88ff5e0447805006b48b8ac6c52dad8e24c7617299e4a46551039841132c3e8ffb8862287"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="0d9a6a03211e1f150d971917fc04c1e98343222c245cdf23543983bf5abfc2c8f5e75174a0bfa85606076cea2ceeb4eb"
    $a9="9a96b4515e4cc95ae6158d76532028c8cf6df26138c17dd221bfc45f6c2074e5d7e713e21c6687b0e88887b5256b37bf"
    $a10="714b7ac92749929c1902ae7a8497bf8da3fb421a3ec4311332053cc43f0994be9b6844f5b34ebd10d6801a1ea2482918"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}