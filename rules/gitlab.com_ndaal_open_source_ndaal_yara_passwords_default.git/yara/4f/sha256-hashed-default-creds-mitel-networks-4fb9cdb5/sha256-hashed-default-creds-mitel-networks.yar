rule sha256_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a6840a79e2e1ce78aa167cb20f5849746987527ed0b19bf8720c4961c329c48"
    $a1="bc4069fb4edf3abf8c5ed5d5b5b15f7b14c2aecdddda4d736930596713932a03"
    $a2="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a3="9c0d294c05fc1d88d698034609bb81c0c69196327594e4c69d2915c80fd9850c"
    $a4="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a5="f4c97d0f07ca354527997e9865f1e197d3917fbfff92a143bb0dab4470deea15"
    $a6="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a7="55da0b2d75f7448a787fca84e3b7052252a69f9c4850a824aa8f0ef475fd610b"
    $a8="4a6840a79e2e1ce78aa167cb20f5849746987527ed0b19bf8720c4961c329c48"
    $a9="b65e5ed8628b3eda27e1cf9aed3ab6ba13a85db081a4f96ecff1f379c240d1e0"
    $a10="9b6a228004f5e21622157867c1155f9b843c7fc1aacf893809fa2b5289a24a4a"
    $a11="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}