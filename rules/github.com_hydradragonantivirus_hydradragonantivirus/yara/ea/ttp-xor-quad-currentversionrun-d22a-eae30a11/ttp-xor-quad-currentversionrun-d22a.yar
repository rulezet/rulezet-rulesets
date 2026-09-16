rule TTP_XOR_QUAD_CurrentVersionRun_d22a {
  strings:
    $key_d22a = { 81 45 [2] a5 4b [2] 8e 67 [2] a0 45 [2] b4 5e [2] bb 44 [2] a5 59 [2] a7 58 [2] bc 5e [2] a0 59 [2] bc 76 }

  condition:
    any of them
}