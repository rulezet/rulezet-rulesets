rule _20160921_4031e49cbb76e44dd58fa572b63a00c7_20160921_7ab823078d23_5028 {
  meta:
    description = "datamaliciousorder - from files 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_7ab823078d2353d978403d071ad27626.js, 20160921_82861e992460412d02ca3f987da7d467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash2       = "32692e808eb087cfb43babd004792978a1918b8bad58bd7576ad1e83a17c97f8"
    hash3       = "2ed6678fea06b2b66ef873575f3af904bb62f54913a37c77387208fd53da33ba"

  strings:
    $s1 = ")(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s2 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(fun" ascii
    $s3 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s4 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s5 = "ion fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}