rule sha3_384_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
    $a2="bdfd8b4bf5911cbe13974f4f89d928b7b6801a95d58c949649271a4fad404b882afc086d8646bbfae01a4810546564dc"
    $a3="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
    $a4="9ffcb76def133c529e40599109e2c7a1192e94cefb8cc34c1d472698603c1e642a88bc74223dd7076cb9a23224464b2e"
    $a5="d9f7085f2e6a7030a3f9d9865a5252c8846e3c9636882967b503713fd4b5d7fdea36e42149ddfe22a7900a7d66097bf1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}