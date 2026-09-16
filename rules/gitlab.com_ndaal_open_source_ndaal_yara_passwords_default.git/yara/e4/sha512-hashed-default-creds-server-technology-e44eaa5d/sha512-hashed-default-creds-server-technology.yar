rule sha512_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="91da79ddf69596bb4144bcb5e9746a811005886be51702ccf51dbfee6855c37ea39672512a0bcb4ec140cd547cf989ec313d230c4537c87de4e62c5878c49e57"
    $a1="ceb9ddeea9f9f20696e71439cddb317be20d7cbd0eb850275d4d1977024f5cca10e7598e316818fd8b52fa92fb3a54287796fa4282c348435c5db3fbb99b96ce"
    $a2="661e5fb8a6902bd9b1ea1ca6e274b716b1f8dca03a13a0860d40cf77aadb4cfc72155cbb1ff858e918a25815398f7045034a0fa4db6ae9f034930fe0d54e5899"
    $a3="70c92f038d4ae10f9609dc7c65dae1c248b8a742d555b1a7a8ecec7e600e41be2b1a0e4a513f77ec45c54098dff28898661dfb68a7521fae1b9b1d133ff6c3d0"
    $a4="8cf561bdff3acfebe7fa18eeb180d2e02cabcbdef59755c906a2d27123290917a4ea152426de267ef6580b3677819c8b6451b4f89f064d423f3e1bd0cadf4d7c"
    $a5="cbf4ee2754f3b81702e85a4dda6a8d53253f7ac68943e96f0e80014cc7e5d2692947d4846aa1902694664a843b96ac6db30d0b84dca141fa29c3869e1ddcf643"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}