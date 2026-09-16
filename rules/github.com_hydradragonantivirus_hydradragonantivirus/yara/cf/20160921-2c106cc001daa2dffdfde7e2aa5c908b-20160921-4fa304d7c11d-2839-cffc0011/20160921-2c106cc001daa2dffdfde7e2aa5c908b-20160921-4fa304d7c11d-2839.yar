rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_4fa304d7c11d_2839 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"

  strings:
    $s1 = "),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii
    $s2 = "turn \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3 = "uck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\"" ascii
    $s4 = "tion fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "rn \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s6 = "ck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"MOj" ascii
    $s7 = "\"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}