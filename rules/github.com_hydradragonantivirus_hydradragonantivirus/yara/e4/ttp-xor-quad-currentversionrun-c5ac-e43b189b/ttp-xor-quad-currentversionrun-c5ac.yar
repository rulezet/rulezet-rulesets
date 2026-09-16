rule TTP_XOR_QUAD_CurrentVersionRun_c5ac {
  strings:
    $key_c5ac = { 96 c3 [2] b2 cd [2] 99 e1 [2] b7 c3 [2] a3 d8 [2] ac c2 [2] b2 df [2] b0 de [2] ab d8 [2] b7 df [2] ab f0 }

  condition:
    any of them
}