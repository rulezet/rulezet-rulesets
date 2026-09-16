rule _20160518_505effd4979f1b3af54b93a3a4421692_20160518_63683f0948a6_1296 {
  meta:
    description = "datamaliciousorder - from files 20160518_505effd4979f1b3af54b93a3a4421692.js, 20160518_63683f0948a6903f2c5e2b30a586af13.js, 20160518_78a3af933132eb51b4004e762f5463e6.js, 20160519_3d9da3a53ffd70b978d4ed841f103b9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8d298aaec8bc80dd4756bbbcc2e288dc65208230d7fb11973df54f5485c9da"
    hash2       = "357674e89a6cbe202f3f6ad1117e58037a35005a84aac1b5e13a75ef36609c73"
    hash3       = "45ef5c2c218bfa7f75362c325002c0197db000856c48080d6754695e3b028597"
    hash4       = "858fcb078addc8021ad3771b25d8b26f40fbe2043e46d5ba43a7bb216c37ecc8"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* u  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* u  */, A8name /* u  *" ascii
    $s3 = "newtonsCradle1 /* u  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* u  */;};" fullword ascii
    $s5 = "dot1 /* u  */= true;/* u  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}