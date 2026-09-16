rule TTP_XOR_QUAD_CurrentVersionRun_d20b {
  strings:
    $key_d20b = { 81 64 [2] a5 6a [2] 8e 46 [2] a0 64 [2] b4 7f [2] bb 65 [2] a5 78 [2] a7 79 [2] bc 7f [2] a0 78 [2] bc 57 }

  condition:
    any of them
}