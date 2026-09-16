rule sha3_384_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="92f70453f8557e5a5b78148358f4f313a8ca005c910c5d47966413a6d7b9424fcd7b769ae05980ddb1e8fb09c5946a21"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="84d7cef64430bcc5b0c8fea8caa3057317547be0a5174370b647ca37a0423da3f5ca75260e2ba37a506ede3025840ded"
    $a5="7e0338df8ce556aa124c77aa3bd1c10b859fccaaa5709847f57cd160c090db39a22baf074a81e7a2b3df10f3fba13898"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}