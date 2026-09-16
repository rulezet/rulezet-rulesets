rule TTP_XOR_QUAD_CurrentVersionRun_98ac {
  strings:
    $key_98ac = { cb c3 [2] ef cd [2] c4 e1 [2] ea c3 [2] fe d8 [2] f1 c2 [2] ef df [2] ed de [2] f6 d8 [2] ea df [2] f6 f0 }

  condition:
    any of them
}