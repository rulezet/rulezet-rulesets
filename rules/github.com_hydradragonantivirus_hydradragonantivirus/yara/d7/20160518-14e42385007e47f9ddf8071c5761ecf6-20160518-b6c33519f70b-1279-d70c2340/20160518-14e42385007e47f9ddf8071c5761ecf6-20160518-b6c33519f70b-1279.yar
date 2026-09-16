rule _20160518_14e42385007e47f9ddf8071c5761ecf6_20160518_b6c33519f70b_1279 {
  meta:
    description = "datamaliciousorder - from files 20160518_14e42385007e47f9ddf8071c5761ecf6.js, 20160518_b6c33519f70b94636bcc4c502b4dbf5b.js, 20160519_629a3c670e54acc4fe1211022c014380.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c9c83a1297664f910244a038e3ce574b15ff94675f0a3b56f90b23c93b98152"
    hash2       = "90cc77b510288b7def290206f642da0a76ea0dda69fe45098a046e6c536bee6a"
    hash3       = "cc495ce25b9a41452f730db0be56a922521dab9493970314526ce440a8b82dee"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* b  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* b  */;};" fullword ascii
    $s3 = "dot1 /* b  */= true;/* b  */" fullword ascii
    $s4 = "newtonsCradle1 /* b  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* b  */, A8name /* b  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}