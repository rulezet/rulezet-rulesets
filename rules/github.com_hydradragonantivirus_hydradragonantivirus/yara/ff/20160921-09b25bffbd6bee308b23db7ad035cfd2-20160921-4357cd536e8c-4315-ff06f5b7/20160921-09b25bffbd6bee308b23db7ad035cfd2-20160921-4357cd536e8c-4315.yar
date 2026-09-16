rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_4357cd536e8c_4315 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash3       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash4       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash5       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash6       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash7       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash8       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash9       = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"

  strings:
    $s1 = "unction f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){retu" ascii
    $s2 = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(fun" ascii
    $s4 = "00(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\"" ascii
    $s5 = "eturn \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}