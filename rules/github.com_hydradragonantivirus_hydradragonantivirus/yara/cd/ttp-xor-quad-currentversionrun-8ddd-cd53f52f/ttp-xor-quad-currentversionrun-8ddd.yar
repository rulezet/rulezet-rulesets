rule TTP_XOR_QUAD_CurrentVersionRun_8ddd {
  strings:
    $key_8ddd = { de b2 [2] fa bc [2] d1 90 [2] ff b2 [2] eb a9 [2] e4 b3 [2] fa ae [2] f8 af [2] e3 a9 [2] ff ae [2] e3 81 }

  condition:
    any of them
}