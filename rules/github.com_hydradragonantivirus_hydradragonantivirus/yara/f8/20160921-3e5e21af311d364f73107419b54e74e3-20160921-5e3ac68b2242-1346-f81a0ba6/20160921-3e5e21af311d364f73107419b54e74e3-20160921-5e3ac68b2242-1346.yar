rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_5e3ac68b2242_1346 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_5e3ac68b2242250176f3300039d176f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"

  strings:
    $s1  = "tion f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return" ascii
    $s2  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IP" ascii
    $s3  = "\"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(func" ascii
    $s4  = "){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})" ascii
    $s5  = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s6  = "(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){" ascii
    $s7  = "on f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"" ascii
    $s8  = "00(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";" ascii
    $s9  = "urn \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s10 = " \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(fu" ascii
    $s11 = "g\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s12 = "Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s13 = "{return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZIi\";})()" ascii
    $s14 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"NYh\";})(),(function f00" ascii
    $s15 = "tion f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}