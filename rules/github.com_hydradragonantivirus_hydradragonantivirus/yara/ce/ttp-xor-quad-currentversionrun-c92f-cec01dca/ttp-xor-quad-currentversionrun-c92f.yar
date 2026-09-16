rule TTP_XOR_QUAD_CurrentVersionRun_c92f {
  strings:
    $key_c92f = { 9a 40 [2] be 4e [2] 95 62 [2] bb 40 [2] af 5b [2] a0 41 [2] be 5c [2] bc 5d [2] a7 5b [2] bb 5c [2] a7 73 }

  condition:
    any of them
}