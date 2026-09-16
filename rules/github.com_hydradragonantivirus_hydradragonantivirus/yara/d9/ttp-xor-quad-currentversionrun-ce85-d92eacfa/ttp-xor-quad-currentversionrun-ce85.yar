rule TTP_XOR_QUAD_CurrentVersionRun_ce85 {
  strings:
    $key_ce85 = { 9d ea [2] b9 e4 [2] 92 c8 [2] bc ea [2] a8 f1 [2] a7 eb [2] b9 f6 [2] bb f7 [2] a0 f1 [2] bc f6 [2] a0 d9 }

  condition:
    any of them
}