rule _20160518_712e5205ec4064c225ba47565740ce1a_20160518_92e779245b08_1307 {
  meta:
    description = "datamaliciousorder - from files 20160518_712e5205ec4064c225ba47565740ce1a.js, 20160518_92e779245b082efd94ee53e942f0c8c4.js, 20160518_a701edf4dd8f8875429f9d90e7b94b2e.js, 20160518_b523726ad23f7a5b5b9e8fe769743ede.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bbcf6d353bc1d2d7a65c51b5475c4ed281f90acebc002a7fa39263a95630a0b"
    hash2       = "0ed855e81551a316786d2dfa421a087f12e4ba36f2d6c0d1b97e5515c31bd772"
    hash3       = "7d7b0f0afeee0420775c89d4b1a1b73b48da403e0a6b1ac1aeed3f2457a68aea"
    hash4       = "c9a00806c16dc88497a9d44b7f741bbbd78d1adb11773f81161eda88317c374e"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* h  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* h  */= true;/* h  */" fullword ascii
    $s3 = "newtonsCradle1 /* h  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* h  */, A8name /* h  *" ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* h  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}