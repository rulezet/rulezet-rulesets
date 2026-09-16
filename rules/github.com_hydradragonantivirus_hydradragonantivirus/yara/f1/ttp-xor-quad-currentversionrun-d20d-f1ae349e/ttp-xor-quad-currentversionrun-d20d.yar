rule TTP_XOR_QUAD_CurrentVersionRun_d20d {
  strings:
    $key_d20d = { 81 62 [2] a5 6c [2] 8e 40 [2] a0 62 [2] b4 79 [2] bb 63 [2] a5 7e [2] a7 7f [2] bc 79 [2] a0 7e [2] bc 51 }

  condition:
    any of them
}