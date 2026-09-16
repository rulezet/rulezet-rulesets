rule TTP_XOR_QUAD_CurrentVersionRun_c6b1 {
  strings:
    $key_c6b1 = { 95 de [2] b1 d0 [2] 9a fc [2] b4 de [2] a0 c5 [2] af df [2] b1 c2 [2] b3 c3 [2] a8 c5 [2] b4 c2 [2] a8 ed }

  condition:
    any of them
}