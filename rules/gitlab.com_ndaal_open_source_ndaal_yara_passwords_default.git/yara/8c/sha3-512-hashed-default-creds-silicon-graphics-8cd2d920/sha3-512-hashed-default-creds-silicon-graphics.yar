rule sha3_512_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a1="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a2="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a3="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a4="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a5="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a6="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
    $a7="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}