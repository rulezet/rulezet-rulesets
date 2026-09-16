rule mysql41_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*834E5ABDA11B90ACCD53F8A58ADB74BAEDF10A4E"
    $a1="*63D67249EE6F30FA6035CE6ECFD15AD4A819AD31"
    $a2="*ECF539683F31FAF543402B3485174D06503B7CF1"
    $a3="*F75A41E3A5599F95AA45F7478DDF6B4168CCE9AC"
    $a4="*3D812CFE4DB597C14246CAD717EF300A1BE37746"
    $a5="*AABF6C9823717E37CCCA340A8F4288B2020937B8"
    $a6="*774FA2FA1ADD6B6FF33800C6F8A930A80CCB7A2D"
    $a7="*972AD278CD622BF02F31BA6B6BACE2EB76E8BC16"
    $a8="*2830FD034FEEAE3E127764717370D23AA2EA0193"
    $a9="*2830FD034FEEAE3E127764717370D23AA2EA0193"
    $a10="*7FA233B59BA76A888EAD790ED048F06BC11DD722"
    $a11="*7FA233B59BA76A888EAD790ED048F06BC11DD722"
    $a12="*DD3E6365EB2362570A9F163830B63D39B1089728"
    $a13="*DD3E6365EB2362570A9F163830B63D39B1089728"
    $a14="*4C1A14ED99A46D099D44B73D30DAFA1C12DAE5B6"
    $a15="*4C1A14ED99A46D099D44B73D30DAFA1C12DAE5B6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}