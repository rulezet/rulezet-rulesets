rule nthash_hashed_default_creds_unisys
{
    meta:
        id = "1Z6cEKCkAydTtmaTUY3ufJ"
        fingerprint = "1fbdfbd6b434dbc57f9d08c8f6722d7a210331732678eec3950fec570e42934a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98b724d9e8ea876a5c3133dd9df97a24"
    $a1="98b724d9e8ea876a5c3133dd9df97a24"
    $a2="c37fbc56ce8d06beb4bc74288b191716"
    $a3="c37fbc56ce8d06beb4bc74288b191716"
    $a4="ee39feb87dd9a2f0fa3e2bf5722682f7"
    $a5="ee39feb87dd9a2f0fa3e2bf5722682f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}