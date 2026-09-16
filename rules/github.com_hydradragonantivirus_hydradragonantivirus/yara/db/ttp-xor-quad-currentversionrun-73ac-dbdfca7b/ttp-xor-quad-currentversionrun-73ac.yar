rule TTP_XOR_QUAD_CurrentVersionRun_73ac {
  strings:
    $key_73ac = { 20 c3 [2] 04 cd [2] 2f e1 [2] 01 c3 [2] 15 d8 [2] 1a c2 [2] 04 df [2] 06 de [2] 1d d8 [2] 01 df [2] 1d f0 }

  condition:
    any of them
}