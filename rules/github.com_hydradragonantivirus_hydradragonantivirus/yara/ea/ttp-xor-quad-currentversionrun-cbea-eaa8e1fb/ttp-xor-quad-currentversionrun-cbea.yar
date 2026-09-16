rule TTP_XOR_QUAD_CurrentVersionRun_cbea {
  strings:
    $key_cbea = { 98 85 [2] bc 8b [2] 97 a7 [2] b9 85 [2] ad 9e [2] a2 84 [2] bc 99 [2] be 98 [2] a5 9e [2] b9 99 [2] a5 b6 }

  condition:
    any of them
}