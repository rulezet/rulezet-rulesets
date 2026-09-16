rule TTP_XOR_QUAD_CurrentVersionRun_41ac {
  strings:
    $key_41ac = { 12 c3 [2] 36 cd [2] 1d e1 [2] 33 c3 [2] 27 d8 [2] 28 c2 [2] 36 df [2] 34 de [2] 2f d8 [2] 33 df [2] 2f f0 }

  condition:
    any of them
}