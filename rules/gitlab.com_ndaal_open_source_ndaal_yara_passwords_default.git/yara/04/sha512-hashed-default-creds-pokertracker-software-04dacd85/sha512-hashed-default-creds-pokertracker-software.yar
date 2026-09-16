rule sha512_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd9d3f0c2eb9893754f4ca53779e8bfe514a1c61d5e44526a323151cc5b34b742a41f79feb02d6f2e581c173fd55e73a3dfa96f6f720f1e4b035a62f72565b45"
    $a1="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
    $a2="783df3fe6ab1cee1f6cd60dec3362abb74ada7cbdf9bac6fde6a32514f52de83c69193a9004b2008480cff495ea57d0fc67cb07a93d7aeced5ddfb1821d267b9"
    $a3="3bb2dc46d0ec0412ebd5007ecbaf22c5b778409ba4f05dba00e00a9fff3579036e9608117e9e88b1d563b09ccfce36973456f1fd389db4da65f3655f4411c241"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}