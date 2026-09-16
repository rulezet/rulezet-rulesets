rule sha3_512_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95d19497c55bafef486116a28077cf87d1c337aac464f852506405b69c2f257bd4670b487720fc68d41dc1adb4fa30ad51ca4522f1a3a4042ab9b43cbc627c63"
    $a1="95d19497c55bafef486116a28077cf87d1c337aac464f852506405b69c2f257bd4670b487720fc68d41dc1adb4fa30ad51ca4522f1a3a4042ab9b43cbc627c63"
    $a2="929d421f4c84e50e23d949d1cce848a744df6e86dc6fe1b5f24095b27b3b4b702775938cbd891e00ed7d3d75fe453badc0c8cd5c13ec5dc458a7353c01085c07"
    $a3="15a7d68e57985306ab5af5a3ced1db30f6f1132b77b47ab54c58ed402f727d360bd0f00e04c6c2890fa61a57f32fed64ba8b36784b6bb30f7dee5b948f1db822"
    $a4="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a5="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a6="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
    $a7="3544701b1b3c664c4bde932492c6ef3bef31dbe7d16ad4a0ffd1fbae0e91cce47280684989f6353e129438011bface3102304efc6df34585241148b5d94f2977"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}