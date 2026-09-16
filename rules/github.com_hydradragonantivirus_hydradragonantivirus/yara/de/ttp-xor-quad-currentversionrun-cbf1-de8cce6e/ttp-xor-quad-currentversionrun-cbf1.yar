rule TTP_XOR_QUAD_CurrentVersionRun_cbf1 {
  strings:
    $key_cbf1 = { 98 9e [2] bc 90 [2] 97 bc [2] b9 9e [2] ad 85 [2] a2 9f [2] bc 82 [2] be 83 [2] a5 85 [2] b9 82 [2] a5 ad }

  condition:
    any of them
}