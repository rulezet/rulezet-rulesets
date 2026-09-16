rule TTP_XOR_QUAD_CurrentVersionRun_d512 {
  strings:
    $key_d512 = { 86 7d [2] a2 73 [2] 89 5f [2] a7 7d [2] b3 66 [2] bc 7c [2] a2 61 [2] a0 60 [2] bb 66 [2] a7 61 [2] bb 4e }

  condition:
    any of them
}