rule _20160518_29d9fef8c03be9adcd534013acb5cb5d_20160518_6ffd92126c21_1287 {
  meta:
    description = "datamaliciousorder - from files 20160518_29d9fef8c03be9adcd534013acb5cb5d.js, 20160518_6ffd92126c21b25e3a899d1453ff633b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97396a80a49aa2ba20e00e468283e085e5326fcd0ba6999683fa7b51ede29dc3"
    hash2       = "2370d53ecbf71d53e5528cb62d0995b65c8d9edbecfca38460b7bfe192035983"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* K  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* K  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* K  */;};" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* K  */, A8name /* K  *" ascii
    $s5 = "dot1 /* K  */= true;/* K  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}