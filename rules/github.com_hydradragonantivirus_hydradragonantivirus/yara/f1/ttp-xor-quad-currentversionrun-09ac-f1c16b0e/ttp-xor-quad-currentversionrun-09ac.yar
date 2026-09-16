rule TTP_XOR_QUAD_CurrentVersionRun_09ac {
  strings:
    $key_09ac = { 5a c3 [2] 7e cd [2] 55 e1 [2] 7b c3 [2] 6f d8 [2] 60 c2 [2] 7e df [2] 7c de [2] 67 d8 [2] 7b df [2] 67 f0 }

  condition:
    any of them
}