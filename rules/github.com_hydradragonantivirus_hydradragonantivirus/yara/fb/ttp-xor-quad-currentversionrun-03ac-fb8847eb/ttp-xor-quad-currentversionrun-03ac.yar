rule TTP_XOR_QUAD_CurrentVersionRun_03ac {
  strings:
    $key_03ac = { 50 c3 [2] 74 cd [2] 5f e1 [2] 71 c3 [2] 65 d8 [2] 6a c2 [2] 74 df [2] 76 de [2] 6d d8 [2] 71 df [2] 6d f0 }

  condition:
    any of them
}