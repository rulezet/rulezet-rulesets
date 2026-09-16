rule _20160921_4031e49cbb76e44dd58fa572b63a00c7_20160921_4d30edc3a4e3_3697 {
  meta:
    description = "datamaliciousorder - from files 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"

  strings:
    $s1 = "eturn \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s2 = "\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function f" ascii
    $s3 = "n \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = "fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "on fuck(){return \"Jh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s6 = "unction fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}