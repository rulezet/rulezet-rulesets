rule TTP_XOR_QUAD_CurrentVersionRun_c931 {
  strings:
    $key_c931 = { 9a 5e [2] be 50 [2] 95 7c [2] bb 5e [2] af 45 [2] a0 5f [2] be 42 [2] bc 43 [2] a7 45 [2] bb 42 [2] a7 6d }

  condition:
    any of them
}