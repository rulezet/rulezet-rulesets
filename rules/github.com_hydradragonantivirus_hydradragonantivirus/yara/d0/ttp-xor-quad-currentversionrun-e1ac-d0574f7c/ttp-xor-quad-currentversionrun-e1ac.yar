rule TTP_XOR_QUAD_CurrentVersionRun_e1ac {
  strings:
    $key_e1ac = { b2 c3 [2] 96 cd [2] bd e1 [2] 93 c3 [2] 87 d8 [2] 88 c2 [2] 96 df [2] 94 de [2] 8f d8 [2] 93 df [2] 8f f0 }

  condition:
    any of them
}