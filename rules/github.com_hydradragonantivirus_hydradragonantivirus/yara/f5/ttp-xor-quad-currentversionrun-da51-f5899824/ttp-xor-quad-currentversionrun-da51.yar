rule TTP_XOR_QUAD_CurrentVersionRun_da51 {
  strings:
    $key_da51 = { 89 3e [2] ad 30 [2] 86 1c [2] a8 3e [2] bc 25 [2] b3 3f [2] ad 22 [2] af 23 [2] b4 25 [2] a8 22 [2] b4 0d }

  condition:
    any of them
}