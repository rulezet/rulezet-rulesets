rule TTP_XOR_QUAD_CurrentVersionRun_da42 {
  strings:
    $key_da42 = { 89 2d [2] ad 23 [2] 86 0f [2] a8 2d [2] bc 36 [2] b3 2c [2] ad 31 [2] af 30 [2] b4 36 [2] a8 31 [2] b4 1e }

  condition:
    any of them
}