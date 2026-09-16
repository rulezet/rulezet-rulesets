rule blake2s_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05cd86ab7af5c5aee421b54cf2745cf049ec90e87a5cfad2bd55c662ec920271"
    $a1="05cd86ab7af5c5aee421b54cf2745cf049ec90e87a5cfad2bd55c662ec920271"
    $a2="05411fb85cfe468c455984021a6a07b6aa33d2822861d238361afe5868ceb7de"
    $a3="beaea7fe492e01ffc908306e5a00f505281806dfd7777e7370c7b03946c0cf6e"
    $a4="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a5="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a6="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
    $a7="d0f9a7487b9993af9e680124b91a9f3b7de5839d3a7045fd459696932c991c1a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}