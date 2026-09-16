rule TTP_XOR_QUAD_CurrentVersionRun_ced6 {
  strings:
    $key_ced6 = { 9d b9 [2] b9 b7 [2] 92 9b [2] bc b9 [2] a8 a2 [2] a7 b8 [2] b9 a5 [2] bb a4 [2] a0 a2 [2] bc a5 [2] a0 8a }

  condition:
    any of them
}