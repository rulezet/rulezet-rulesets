rule blake2b_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a1="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a2="5e8e072518d25e500a131b451a0e9bf089aef55b5af76c03c46c7c306640cea04505a352e4bb5ab09fad233812b8f76ae3bd1a66c3077e143c7bf3c2517726be"
    $a3="c1f8301053790b64ed15002901d229b046f2a0c87c1535b08629b3d0004e4f0da9bb5182df192c757150fc7fc813c80e352f2b90e284c488a27346aa90abf8e2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}