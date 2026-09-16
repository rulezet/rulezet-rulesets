rule sha224_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="93c44a79a10e9e4472c6a49d95472fc7e40f2d67f38369510cd5ec52"
    $a1="611e895d6028d7dd1236dd419c2886e66abd9ba0086220fe8a586bc5"
    $a2="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a3="c23b4b05a88545c92b14e2f27cd39aeb442dc816eac8c96db34c6076"
    $a4="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a5="c99a6d7630d8c28a5c9b865d58bb9ca780d5749f240162eeec39b1f0"
    $a6="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a7="83bb3fc47ac1f7a55e18a113dc40c4a5222aa313e4a017fa4c61cf37"
    $a8="93c44a79a10e9e4472c6a49d95472fc7e40f2d67f38369510cd5ec52"
    $a9="d2f794a490b54343929f420853c953465b95990d631664ce37d4e543"
    $a10="7d4edbe25b56f378a3090837ed7849225810d0a8cc1d0935b7982144"
    $a11="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}