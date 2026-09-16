rule TTP_XOR_QUAD_CurrentVersionRun_d551 {
  strings:
    $key_d551 = { 86 3e [2] a2 30 [2] 89 1c [2] a7 3e [2] b3 25 [2] bc 3f [2] a2 22 [2] a0 23 [2] bb 25 [2] a7 22 [2] bb 0d }

  condition:
    any of them
}