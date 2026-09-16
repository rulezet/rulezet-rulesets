rule blake2b_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f712995205f25355869b6aaba277ef26e231f6473c22d0292fae013a158f157af2a3527f87ba0be2ed08ecdacda5f503246a91291a6cd2f9ec7df407dd1b5c8"
    $a1="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a2="9d0cdc80d29977b52125ac1e933f95e8d41e0de299291e4e2d8659883dd1f3b7d15c4d4422433259bbaab04eb2021d8d83d79f02fed263509b1df6eff0e1c726"
    $a3="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}