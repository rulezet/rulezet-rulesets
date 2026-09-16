rule TTP_XOR_QUAD_CurrentVersionRun_d22b {
  strings:
    $key_d22b = { 81 44 [2] a5 4a [2] 8e 66 [2] a0 44 [2] b4 5f [2] bb 45 [2] a5 58 [2] a7 59 [2] bc 5f [2] a0 58 [2] bc 77 }

  condition:
    any of them
}