rule TTP_XOR_QUAD_CurrentVersionRun_ce06 {
  strings:
    $key_ce06 = { 9d 69 [2] b9 67 [2] 92 4b [2] bc 69 [2] a8 72 [2] a7 68 [2] b9 75 [2] bb 74 [2] a0 72 [2] bc 75 [2] a0 5a }

  condition:
    any of them
}