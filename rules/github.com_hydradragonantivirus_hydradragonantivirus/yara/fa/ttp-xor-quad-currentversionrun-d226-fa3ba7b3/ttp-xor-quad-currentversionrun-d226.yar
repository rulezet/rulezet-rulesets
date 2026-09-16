rule TTP_XOR_QUAD_CurrentVersionRun_d226 {
  strings:
    $key_d226 = { 81 49 [2] a5 47 [2] 8e 6b [2] a0 49 [2] b4 52 [2] bb 48 [2] a5 55 [2] a7 54 [2] bc 52 [2] a0 55 [2] bc 7a }

  condition:
    any of them
}