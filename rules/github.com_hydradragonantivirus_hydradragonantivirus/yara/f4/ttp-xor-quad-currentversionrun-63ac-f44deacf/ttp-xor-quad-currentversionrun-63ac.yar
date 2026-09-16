rule TTP_XOR_QUAD_CurrentVersionRun_63ac {
  strings:
    $key_63ac = { 30 c3 [2] 14 cd [2] 3f e1 [2] 11 c3 [2] 05 d8 [2] 0a c2 [2] 14 df [2] 16 de [2] 0d d8 [2] 11 df [2] 0d f0 }

  condition:
    any of them
}