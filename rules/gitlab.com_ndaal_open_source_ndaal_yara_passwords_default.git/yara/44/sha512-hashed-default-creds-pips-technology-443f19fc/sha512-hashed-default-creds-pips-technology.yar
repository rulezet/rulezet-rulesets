rule sha512_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcbabc29330396d743b15e1ccabd4dc695400bcce835452038db36740aa6f6fb259ab36d7252b5bd210bfa671a8e541115bc7883db5b083e6b7030d98c0adff"
    $a1="cdcbabc29330396d743b15e1ccabd4dc695400bcce835452038db36740aa6f6fb259ab36d7252b5bd210bfa671a8e541115bc7883db5b083e6b7030d98c0adff"
    $a2="a9766f35b14a93656f1e828266e84eb9329ec81aa782fb63d64204744d8a9d4b13ef9928c47beb64404775b053a27a23ff3c1b1550f0281c78872efcf5a07e1b"
    $a3="a9766f35b14a93656f1e828266e84eb9329ec81aa782fb63d64204744d8a9d4b13ef9928c47beb64404775b053a27a23ff3c1b1550f0281c78872efcf5a07e1b"
    $a4="6523a4937120dd1d8cbe6779e1b24cc509dc2f7c8767015bdd494c9ec4ebf0ca801d24dbd83c8ddccf92c17b78c749b163d2332191bedd06a8ac2ebc3212557c"
    $a5="6523a4937120dd1d8cbe6779e1b24cc509dc2f7c8767015bdd494c9ec4ebf0ca801d24dbd83c8ddccf92c17b78c749b163d2332191bedd06a8ac2ebc3212557c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}