rule TTP_XOR_QUAD_CurrentVersionRun_d7b1 {
  strings:
    $key_d7b1 = { 84 de [2] a0 d0 [2] 8b fc [2] a5 de [2] b1 c5 [2] be df [2] a0 c2 [2] a2 c3 [2] b9 c5 [2] a5 c2 [2] b9 ed }

  condition:
    any of them
}