rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_eb80446b9cea_2132 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1 = "Jm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s2 = "\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "{return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";}" ascii
    $s4 = "nction f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){ret" ascii
    $s5 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(" ascii
    $s6 = "ction f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){retur" ascii
    $s7 = "{return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})" ascii
    $s8 = "(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii
    $s9 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}