rule TTP_XOR_QUAD_CurrentVersionRun_c933 {
  strings:
    $key_c933 = { 9a 5c [2] be 52 [2] 95 7e [2] bb 5c [2] af 47 [2] a0 5d [2] be 40 [2] bc 41 [2] a7 47 [2] bb 40 [2] a7 6f }

  condition:
    any of them
}