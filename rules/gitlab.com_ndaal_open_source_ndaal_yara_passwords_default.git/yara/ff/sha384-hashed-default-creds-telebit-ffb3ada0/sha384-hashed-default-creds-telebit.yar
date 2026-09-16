rule sha384_hashed_default_creds_telebit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a1="daead2f5d798969185c0b94acb330300f835db65a2d91cd4095104d96b469515fce7ab29373dc30cc9ca851059e33e4f"
    $a2="3b67410b602c36730b8572f9cf49383caf0d936a14e7d93d4f0906a3f27d839964a7bf6dd3ffe74f541788c10a53ce6c"
    $a3="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
    $a4="cf8cb7bd641fa46a496514440e4b0698b56e94aef126b960dbf81290fad7117511abfb9d2fa882225cbd94463f549e33"
    $a5="4da496741d104cfac77f429b2c14ae0875a89837302361b7d8dc65dbd523ffa61f850d7ce38b27818299d2ada1aeb99c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}