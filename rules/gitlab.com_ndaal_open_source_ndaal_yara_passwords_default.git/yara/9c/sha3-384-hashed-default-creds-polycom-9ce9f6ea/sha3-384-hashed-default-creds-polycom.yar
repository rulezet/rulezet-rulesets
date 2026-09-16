rule sha3_384_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a1="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a2="d1506f7938bae235ae44b42b10718f3039e9f2f0a2e11df31455fa85ded512c792c5ad66bbf7cc40512f35c336199954"
    $a3="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a4="e9c39d4b15f14239a96991d9628368bfb7fab6ba2a9506574ce22070fc12ab814952fd239e7abf522777460acdc1a8ef"
    $a5="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a6="14e14ff32e7fa536d894bc4926bbcabca700d98b0c743c1ff845dc5e1cd700698b6d559a5895145628bb7bcb95eacf56"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="d5d3a83a2710dfda618f51e0ea1b486218c37ba994054a2297d5b1e31f1d271a42a4238e2dc54c2b20c087ee32599067"
    $a9="02ecd93594f2a0925be878e2c015a211e659ffd2ab94542c2dfab1176e332b2ccd53ca1a945a4abc8edb03a0b4a5b897"
    $a10="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}