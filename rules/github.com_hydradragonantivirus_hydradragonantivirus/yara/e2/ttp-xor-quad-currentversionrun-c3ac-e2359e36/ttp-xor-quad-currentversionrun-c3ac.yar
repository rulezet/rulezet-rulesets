rule TTP_XOR_QUAD_CurrentVersionRun_c3ac {
  strings:
    $key_c3ac = { 90 c3 [2] b4 cd [2] 9f e1 [2] b1 c3 [2] a5 d8 [2] aa c2 [2] b4 df [2] b6 de [2] ad d8 [2] b1 df [2] ad f0 }

  condition:
    any of them
}