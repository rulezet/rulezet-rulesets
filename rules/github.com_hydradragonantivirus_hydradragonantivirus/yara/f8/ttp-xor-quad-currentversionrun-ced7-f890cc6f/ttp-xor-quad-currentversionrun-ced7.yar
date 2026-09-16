rule TTP_XOR_QUAD_CurrentVersionRun_ced7 {
  strings:
    $key_ced7 = { 9d b8 [2] b9 b6 [2] 92 9a [2] bc b8 [2] a8 a3 [2] a7 b9 [2] b9 a4 [2] bb a5 [2] a0 a3 [2] bc a4 [2] a0 8b }

  condition:
    any of them
}