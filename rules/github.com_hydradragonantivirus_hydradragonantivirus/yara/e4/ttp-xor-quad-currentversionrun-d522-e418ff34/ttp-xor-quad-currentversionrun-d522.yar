rule TTP_XOR_QUAD_CurrentVersionRun_d522 {
  strings:
    $key_d522 = { 86 4d [2] a2 43 [2] 89 6f [2] a7 4d [2] b3 56 [2] bc 4c [2] a2 51 [2] a0 50 [2] bb 56 [2] a7 51 [2] bb 7e }

  condition:
    any of them
}