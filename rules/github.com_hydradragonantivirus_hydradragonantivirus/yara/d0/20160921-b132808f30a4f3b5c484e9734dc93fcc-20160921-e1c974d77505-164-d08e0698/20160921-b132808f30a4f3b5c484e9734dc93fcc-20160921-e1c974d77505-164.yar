rule _20160921_b132808f30a4f3b5c484e9734dc93fcc_20160921_e1c974d77505_164 {
  meta:
    description = "datamaliciousorder - from files 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash2       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1  = "nction f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii
    $s2  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return" ascii
    $s3  = "unction f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s4  = "(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){" ascii
    $s5  = "){return \"BMj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s6  = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000()" ascii
    $s7  = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s8  = "0(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";}" ascii
    $s9  = "0(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s10 = "rn \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s11 = "rn \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s12 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz\";}" ascii
    $s13 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s14 = "n\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(functio" ascii
    $s15 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"SGs\";})(),(fun" ascii
    $s16 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vu\";})(),(function f000(){" ascii
    $s17 = "Yx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s18 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(" ascii
    $s19 = "function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){r" ascii
    $s20 = " \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}