rule TTP_XOR_QUAD_CurrentVersionRun_91ac {
  strings:
    $key_91ac = { c2 c3 [2] e6 cd [2] cd e1 [2] e3 c3 [2] f7 d8 [2] f8 c2 [2] e6 df [2] e4 de [2] ff d8 [2] e3 df [2] ff f0 }

  condition:
    any of them
}