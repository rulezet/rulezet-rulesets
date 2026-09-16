rule _20160518_2cd34c0dd3af417abb585ddff9a0ca37_20160519_30cd245f9405_1288 {
  meta:
    description = "datamaliciousorder - from files 20160518_2cd34c0dd3af417abb585ddff9a0ca37.js, 20160519_30cd245f940588fd1852465475b15fbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "311c888286aebc9aa0a55211993611adf5fe3de8e04549a77c4adb3ccaaac6ac"
    hash2       = "3c0470f9ff6bc08fd9abb2897f5e4b103a5f827d51de0c93a33e69da3f6034b3"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* r  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* r  */= true;/* r  */" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* r  */, A8name /* r  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* r  */;};" fullword ascii
    $s5 = "newtonsCradle1 /* r  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}