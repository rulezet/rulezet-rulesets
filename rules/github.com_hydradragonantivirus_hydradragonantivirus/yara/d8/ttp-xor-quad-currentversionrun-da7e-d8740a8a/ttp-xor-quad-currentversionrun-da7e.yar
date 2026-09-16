rule TTP_XOR_QUAD_CurrentVersionRun_da7e {
  strings:
    $key_da7e = { 89 11 [2] ad 1f [2] 86 33 [2] a8 11 [2] bc 0a [2] b3 10 [2] ad 0d [2] af 0c [2] b4 0a [2] a8 0d [2] b4 22 }

  condition:
    any of them
}