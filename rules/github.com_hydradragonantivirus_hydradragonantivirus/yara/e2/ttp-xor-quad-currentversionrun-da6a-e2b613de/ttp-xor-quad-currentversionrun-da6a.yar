rule TTP_XOR_QUAD_CurrentVersionRun_da6a {
  strings:
    $key_da6a = { 89 05 [2] ad 0b [2] 86 27 [2] a8 05 [2] bc 1e [2] b3 04 [2] ad 19 [2] af 18 [2] b4 1e [2] a8 19 [2] b4 36 }

  condition:
    any of them
}