rule _20160802_473b2e30c6e7a5b8782fc8439ac0a28d_20160802_fab6de4ed8f5_719 {
  meta:
    description = "datamaliciousorder - from files 20160802_473b2e30c6e7a5b8782fc8439ac0a28d.js, 20160802_fab6de4ed8f5b24ea776f10c6e213ce2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0add6b970728d7a37093c7c817b151785b0011058ae1aa2aee9d4faafa07eab"
    hash2       = "daab71c547ce5a6bc531a93bcf462e1941df5b5e3736ad2dbbed728e5714ba8f"

  strings:
    $s1 = "\\x20Aa6 = \"pe\"\\x20+\\x20\"\";\\x0d\\nvar M\\x620 \\x3d \\x22ty\" + \"\";\\r\\nvar Si4 = \"o\\x70en\" + \"\";\\r\\nfunction T" ascii
    $s2 = "e\" \\x2b \"\";\\r\\nvar Tw = \"\\x52e\" + \"\"\\x3b\\r\\nf\\x75nc\\x74ion AJ\\x614\\x28Xj6){return Xj6;};funct\\x69on Yc9(G\\x6" ascii
    $s3 = "t4 = \"len\" + \"\";\\r\\nvar \\x59Kl6 =\\x20\"h\" + \"\";\\r\\nva\\x72 Uj = \"gt\" + \"\\x22;\\r\\nvar EOp4 = \"l\\x65n\" + \\x" ascii
    $s4 = "in\" + \"\";\\r\\nfuncti\\x6fn WQh(J\\x6d){return Jm;};\\x66unc\\x74\\x69o\\x6e VWu1\\x28SPi8){r\\x65turn\\x20SPi8;};function Vz" ascii
    $s5 = "x20\\x2b \"\";\\r\\n\\x76ar NMx = \"veTo\\x22 + \"\";\\r\\nvar Y\\x51o = \"Sa\" +\\x20\"\\x22;\\r\\nfunctio\\x6e IDj(Oj9){return" ascii
    $s6 = "6\\x29{ret\\x75rn Ef;};var \\x4aYk =\\x20\"\\x63lo\\x73e\" +\\x20\"\";\\r\\nf\\x75nction\\x20\\x53s(Gh7){return Gh7\\x3b\\x7d;v" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}