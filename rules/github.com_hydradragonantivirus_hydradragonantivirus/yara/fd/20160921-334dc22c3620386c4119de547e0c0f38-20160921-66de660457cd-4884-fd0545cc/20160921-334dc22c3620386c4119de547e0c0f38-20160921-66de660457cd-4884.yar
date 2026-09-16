rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_66de660457cd_4884 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash3       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash4       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "n f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s2 = "rn \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(f" ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return " ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s5 = "{return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}