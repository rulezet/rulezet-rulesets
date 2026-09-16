rule TTP_XOR_QUAD_CurrentVersionRun_69ac {
  strings:
    $key_69ac = { 3a c3 [2] 1e cd [2] 35 e1 [2] 1b c3 [2] 0f d8 [2] 00 c2 [2] 1e df [2] 1c de [2] 07 d8 [2] 1b df [2] 07 f0 }

  condition:
    any of them
}