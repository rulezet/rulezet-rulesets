rule _20160518_167c2d865cb66bee88d770a8920df318_20160518_53aeb32f5856_1282 {
  meta:
    description = "datamaliciousorder - from files 20160518_167c2d865cb66bee88d770a8920df318.js, 20160518_53aeb32f58561653331f4ae33002aeef.js, 20160518_8ec6eab83aaaca71b3de01ec46fd7f22.js, 20160518_d9a1381677b3c290fd2768c65a061ef4.js, 20160518_e316ca10992a55eb8cd2c0eb97e9308d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "371c09e65092adf23a844972c33fe2aa52380338e197f104135a763b00e18980"
    hash2       = "27017f27929fd657bbd89ff010c14e1e9789734a7a9c7f5d3c198289fd7f555f"
    hash3       = "e815acd90e47e41e45df671ae37fdd91bda5770b94ca056b16af1d866abaa9fa"
    hash4       = "416a23f6a42a08ad26b881846215dd4cd339ca83c50725934bb893446663e976"
    hash5       = "e93d899a106eca0959c3e2e9c81aea961e92ded7589e918612f7c034e69b4664"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* o  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* o  */;};" fullword ascii
    $s3 = "dot1 /* o  */= true;/* o  */" fullword ascii
    $s4 = "newtonsCradle1 /* o  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* o  */, A8name /* o  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}