rule sha512_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
    $a3="84148e7732c838449df1db8f9fec13129fd8cee09e0a11b2eecfd384ee30c5b3c7bcf79cf7947d39318d2f5db54c910fade20fc4b1cc1ee66c914c8fce13987d"
    $a4="5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da"
    $a5="c11fc00b41549c865ecc8219948a6a28a6f40671621a1cf1cb9397ae3d597e709163f1d46e627b9a494cebcecefadbef8aaa98f93dc4772a7a3c7ef67edcf0c5"
    $a6="48fb10b15f3d44a09dc82d02b06581e0c0c69478c9fd2cf8f9093659019a1687baecdbb38c9e72b12169dc4148690f87467f9154f5931c5df665c6496cbfd5f5"
    $a7="39c134bcfbea849fc8c7d9eaf102de758d1343f0812e59e98053c14bce3d170f5a59422bbf166ca3543681e6eb3784f3fa171005dc84e5ad8bb136f612e78b0c"
    $a8="f10127742e07a7705735572f823574b89aaf1cbe071935cb9e75e5cfeb817700cb484d1100a10ad5c32b59c3d6565211108aa9ef0611d7ec830c1b66f60e614d"
    $a9="b371870320781e8c85c335dd627125a864c94dd400310ba5aa840bf0386a5b5dc1cc42393017685f80b5a6820ee1444219d32ec968e0f92e2289f05e399ac8d2"
    $a10="f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a"
    $a11="4e956412fd01690ca3c246a1520f1cef9603788fb132f7ae314241100052a7d642aa707e28f039ca62840bddfaf9c3e38735618743d361129a46be4947e25a3b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}