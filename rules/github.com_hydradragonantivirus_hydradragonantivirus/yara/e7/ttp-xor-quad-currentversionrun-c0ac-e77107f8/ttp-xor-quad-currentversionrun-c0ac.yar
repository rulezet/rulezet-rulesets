rule TTP_XOR_QUAD_CurrentVersionRun_c0ac {
  strings:
    $key_c0ac = { 93 c3 [2] b7 cd [2] 9c e1 [2] b2 c3 [2] a6 d8 [2] a9 c2 [2] b7 df [2] b5 de [2] ae d8 [2] b2 df [2] ae f0 }

  condition:
    any of them
}