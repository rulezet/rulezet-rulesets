rule TTP_XOR_QUAD_CurrentVersionRun_c918 {
  strings:
    $key_c918 = { 9a 77 [2] be 79 [2] 95 55 [2] bb 77 [2] af 6c [2] a0 76 [2] be 6b [2] bc 6a [2] a7 6c [2] bb 6b [2] a7 44 }

  condition:
    any of them
}