rule TTP_XOR_QUAD_CurrentVersionRun_d0b1 {
  strings:
    $key_d0b1 = { 83 de [2] a7 d0 [2] 8c fc [2] a2 de [2] b6 c5 [2] b9 df [2] a7 c2 [2] a5 c3 [2] be c5 [2] a2 c2 [2] be ed }

  condition:
    any of them
}