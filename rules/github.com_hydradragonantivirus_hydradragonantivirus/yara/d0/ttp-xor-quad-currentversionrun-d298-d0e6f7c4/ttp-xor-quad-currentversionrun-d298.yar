rule TTP_XOR_QUAD_CurrentVersionRun_d298 {
  strings:
    $key_d298 = { 81 f7 [2] a5 f9 [2] 8e d5 [2] a0 f7 [2] b4 ec [2] bb f6 [2] a5 eb [2] a7 ea [2] bc ec [2] a0 eb [2] bc c4 }

  condition:
    any of them
}