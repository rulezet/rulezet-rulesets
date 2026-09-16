rule TTP_XOR_QUAD_CurrentVersionRun_d52a {
  strings:
    $key_d52a = { 86 45 [2] a2 4b [2] 89 67 [2] a7 45 [2] b3 5e [2] bc 44 [2] a2 59 [2] a0 58 [2] bb 5e [2] a7 59 [2] bb 76 }

  condition:
    any of them
}