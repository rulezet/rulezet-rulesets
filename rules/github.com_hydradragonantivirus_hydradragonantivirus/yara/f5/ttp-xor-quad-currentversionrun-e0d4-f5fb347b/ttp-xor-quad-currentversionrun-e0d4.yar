rule TTP_XOR_QUAD_CurrentVersionRun_e0d4 {
  strings:
    $key_e0d4 = { b3 bb [2] 97 b5 [2] bc 99 [2] 92 bb [2] 86 a0 [2] 89 ba [2] 97 a7 [2] 95 a6 [2] 8e a0 [2] 92 a7 [2] 8e 88 }

  condition:
    any of them
}