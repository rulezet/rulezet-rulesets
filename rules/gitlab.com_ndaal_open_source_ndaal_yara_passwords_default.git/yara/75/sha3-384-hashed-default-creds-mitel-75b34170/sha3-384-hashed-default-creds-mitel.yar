rule sha3_384_hashed_default_creds_mitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a2="78a64f797e9b1b1b2c93c298872e750df0786e31c30a8d277a01acb8052c6021ffaf004dc8ecc7966491be148aa7d2cf"
    $a3="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a4="e00dc50afedcce026b1f7cae071bb78721ebf4f61149ce3b3f968cae250cc08485d03c7d0da28616527d5a8359f842c8"
    $a5="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a6="5397476ada680c1c22bc89e65ec2362c0b2c0ec961241d95613422c8d1890304373908b86b00b6559f87e5ded6cfbd90"
    $a7="18b54a8de3ef7af582050541d99e85e583708db04970f30d1fbbbe5bd22a3926c2147939e2be80a83b4f325ad72cd7fe"
    $a8="429ac44955752ea87f553303d485b159ccf39873bdab5da9acaff9cfe393ad413aca035d907a58d1e860e850fefcbc51"
    $a9="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a10="6bdc1b784f4a65070782b0168fe535716083235d6de618c10a913145b5d78669e7565a1cdaba90a417d4641d95dc02c0"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}