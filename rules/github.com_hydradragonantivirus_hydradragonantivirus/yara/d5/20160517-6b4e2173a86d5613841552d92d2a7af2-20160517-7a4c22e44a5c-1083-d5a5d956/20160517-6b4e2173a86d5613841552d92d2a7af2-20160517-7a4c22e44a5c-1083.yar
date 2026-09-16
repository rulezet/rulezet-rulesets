rule _20160517_6b4e2173a86d5613841552d92d2a7af2_20160517_7a4c22e44a5c_1083 {
  meta:
    description = "datamaliciousorder - from files 20160517_6b4e2173a86d5613841552d92d2a7af2.js, 20160517_7a4c22e44a5ced5aeb9a276e82c0f74f.js, 20160517_82067dc333dfc44137c13677414507d9.js, 20160517_f592e496d142a026f687c729eb343784.js, 20160517_fe820e7582688abb18bc754abce9f66f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f64233eb6540923d037a14b490938948de9a604fd3a998df8090ae1666ec68b7"
    hash2       = "e5e050df51795a5ea2500adf311a098aa133cf5e233809856fdaf4ef3dfb5625"
    hash3       = "3b2d182209ff6cb1ba70eb7f1438f112af8935b351ba62abb17fc4c6f54dd0d7"
    hash4       = "8cacc9b0073bb6e7b5f4f290f64af27ef1aa3cff5803acf5189a0dff20099899"
    hash5       = "94ff6f20d330351d3efcf92777dea40ec387fdf014c9f8ed48873cf10f6dff23"

  strings:
    $s1 = "var nConverts1 /* T  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* T  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* T  */;};" fullword ascii
    $s4 = "var enjoy1 /* T  */ = false;" fullword ascii
    $s5 = "batch =/* T  */ \"R\" + \"esponseB\"/* T  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* T  */(/* T  */\"noitisop\").split(''/* T  */).reverse(/* T  */).join('');" fullword ascii
    $s7 = "enjoy1 /* T  */ /* T  */= true;/* T  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}