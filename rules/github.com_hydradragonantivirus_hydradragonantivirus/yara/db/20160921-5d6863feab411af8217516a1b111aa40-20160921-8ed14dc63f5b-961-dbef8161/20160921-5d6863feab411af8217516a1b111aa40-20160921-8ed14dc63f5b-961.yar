rule _20160921_5d6863feab411af8217516a1b111aa40_20160921_8ed14dc63f5b_961 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"

  strings:
    $s1  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IAa\";})(),(f" ascii
    $s2  = "ion f000(){return \"Um\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s3  = "nction f000(){return \"Vj\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4  = "{return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})" ascii
    $s5  = ",(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){" ascii
    $s6  = " \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s7  = ")(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s8  = "\"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s9  = ")(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s10 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(functio" ascii
    $s11 = "urn \"Yv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OMd\";})(),(f" ascii
    $s12 = " f000(){return \"MMz\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MD" ascii
    $s13 = "tion f000(){return \"DYs\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s14 = "Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s15 = "f000(){return \"Wb\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SE" ascii
    $s16 = "turn \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s17 = ")(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s18 = ";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f0" ascii
    $s19 = "function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){re" ascii
    $s20 = ";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}