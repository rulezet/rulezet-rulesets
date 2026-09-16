rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_b132808f30a4_370 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1  = "000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz" ascii
    $s2  = "tion f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s3  = "0(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\"" ascii
    $s4  = "ction f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s5  = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s6  = " f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s7  = "n f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s8  = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f" ascii
    $s9  = "n f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s10 = "})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii
    $s11 = "eturn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s12 = "(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s13 = "rn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s14 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000()" ascii
    $s15 = "n \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s16 = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(" ascii
    $s17 = " f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Z" ascii
    $s18 = "(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(" ascii
    $s19 = "eturn \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})()," ascii
    $s20 = "),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}