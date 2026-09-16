rule TTP_XOR_QUAD_CurrentVersionRun_c932 {
  strings:
    $key_c932 = { 9a 5d [2] be 53 [2] 95 7f [2] bb 5d [2] af 46 [2] a0 5c [2] be 41 [2] bc 40 [2] a7 46 [2] bb 41 [2] a7 6e }

  condition:
    any of them
}