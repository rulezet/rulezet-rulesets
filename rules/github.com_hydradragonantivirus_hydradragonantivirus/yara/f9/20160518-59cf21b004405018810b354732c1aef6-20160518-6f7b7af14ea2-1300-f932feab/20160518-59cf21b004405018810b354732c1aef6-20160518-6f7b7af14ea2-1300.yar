rule _20160518_59cf21b004405018810b354732c1aef6_20160518_6f7b7af14ea2_1300 {
  meta:
    description = "datamaliciousorder - from files 20160518_59cf21b004405018810b354732c1aef6.js, 20160518_6f7b7af14ea260056ae686c7b1a2f0d6.js, 20160518_dd5981dfc5ccb7eb422a98bba4752648.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b186f642cd25931f10a390846ad60a4d3c7dc8aa925c0db91b0db73544da640d"
    hash2       = "f8422f71d835e0e5ceecfa9c96f2c0c7bb528fc49ffc5c491b138a1de5bb18ea"
    hash3       = "06b98b3153f0d19333fda63b1c9b1848eb10cab20862a1a698df2041eeb162b2"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* l  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* l  */= true;/* l  */" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* l  */, A8name /* l  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* l  */;};" fullword ascii
    $s5 = "newtonsCradle1 /* l  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}