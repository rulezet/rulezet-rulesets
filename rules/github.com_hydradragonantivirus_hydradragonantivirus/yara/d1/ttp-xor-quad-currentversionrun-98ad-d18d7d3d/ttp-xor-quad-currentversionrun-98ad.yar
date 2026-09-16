rule TTP_XOR_QUAD_CurrentVersionRun_98ad {
  strings:
    $key_98ad = { cb c2 [2] ef cc [2] c4 e0 [2] ea c2 [2] fe d9 [2] f1 c3 [2] ef de [2] ed df [2] f6 d9 [2] ea de [2] f6 f1 }

  condition:
    any of them
}