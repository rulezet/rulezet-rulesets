rule _20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5_20160921_5f5611940db7_5278 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s2 = "ction f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return" ascii
    $s3 = "f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp" ascii
    $s4 = "KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}