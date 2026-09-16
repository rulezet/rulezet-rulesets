rule TTP_XOR_QUAD_CurrentVersionRun_ce96 {
  strings:
    $key_ce96 = { 9d f9 [2] b9 f7 [2] 92 db [2] bc f9 [2] a8 e2 [2] a7 f8 [2] b9 e5 [2] bb e4 [2] a0 e2 [2] bc e5 [2] a0 ca }

  condition:
    any of them
}