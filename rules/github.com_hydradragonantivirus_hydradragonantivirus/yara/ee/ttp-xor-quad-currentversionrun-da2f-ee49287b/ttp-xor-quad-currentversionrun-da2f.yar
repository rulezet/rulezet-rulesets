rule TTP_XOR_QUAD_CurrentVersionRun_da2f {
  strings:
    $key_da2f = { 89 40 [2] ad 4e [2] 86 62 [2] a8 40 [2] bc 5b [2] b3 41 [2] ad 5c [2] af 5d [2] b4 5b [2] a8 5c [2] b4 73 }

  condition:
    any of them
}