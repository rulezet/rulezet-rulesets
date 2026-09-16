rule sha3_512_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9acd135acc5c8e26c5e37b13a3155f86480965c9d23244cede6bb1367d1ea378f54add8807cd1eb1be776d5250bd32aa399675ebfede46d3d999e8a1583475d0"
    $a1="9acd135acc5c8e26c5e37b13a3155f86480965c9d23244cede6bb1367d1ea378f54add8807cd1eb1be776d5250bd32aa399675ebfede46d3d999e8a1583475d0"
    $a2="6e689567094266398a2923bee3d0516919e08ce588ca8bff9bfa67259a0dc71403c136d0d49cf3dd6fcd61307aad578b4a00e6479648809fd25dc17edf63dc7f"
    $a3="e580eb9fe88a5e5c44f905cae25bedefc7dd5da58e068fe9503dd9bdca83756e68adea3a31dcc1bf33403ecec073f2c378ada046859afd2034cf95cb91f8c754"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}