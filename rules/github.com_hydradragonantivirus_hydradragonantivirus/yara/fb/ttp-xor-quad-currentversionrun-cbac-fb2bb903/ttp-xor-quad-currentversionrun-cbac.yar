rule TTP_XOR_QUAD_CurrentVersionRun_cbac {
  strings:
    $key_cbac = { 98 c3 [2] bc cd [2] 97 e1 [2] b9 c3 [2] ad d8 [2] a2 c2 [2] bc df [2] be de [2] a5 d8 [2] b9 df [2] a5 f0 }

  condition:
    any of them
}