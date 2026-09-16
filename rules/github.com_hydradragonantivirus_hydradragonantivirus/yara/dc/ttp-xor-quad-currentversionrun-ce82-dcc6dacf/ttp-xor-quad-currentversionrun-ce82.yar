rule TTP_XOR_QUAD_CurrentVersionRun_ce82 {
  strings:
    $key_ce82 = { 9d ed [2] b9 e3 [2] 92 cf [2] bc ed [2] a8 f6 [2] a7 ec [2] b9 f1 [2] bb f0 [2] a0 f6 [2] bc f1 [2] a0 de }

  condition:
    any of them
}