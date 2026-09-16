rule TTP_XOR_QUAD_CurrentVersionRun_c9f1 {
  strings:
    $key_c9f1 = { 9a 9e [2] be 90 [2] 95 bc [2] bb 9e [2] af 85 [2] a0 9f [2] be 82 [2] bc 83 [2] a7 85 [2] bb 82 [2] a7 ad }

  condition:
    any of them
}