rule _20160518_6b2f980e0bd765eb3acd52c26470fe27_20160518_d0cd4b4b8db8_1303 {
  meta:
    description = "datamaliciousorder - from files 20160518_6b2f980e0bd765eb3acd52c26470fe27.js, 20160518_d0cd4b4b8db8d4cb62fd8410b943950e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "237ff520f0f831e6b57e121dc905151019e5bc6a2eba3ac3a83e6a185aab4a76"
    hash2       = "62dbcc7eb210a5f64ccb0909f1c6b98b463112d80329bfd54d5db06456645667"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* X  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* X  */, A8name /* X  *" ascii
    $s3 = "dot1 /* X  */= true;/* X  */" fullword ascii
    $s4 = "newtonsCradle1 /* X  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* X  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}