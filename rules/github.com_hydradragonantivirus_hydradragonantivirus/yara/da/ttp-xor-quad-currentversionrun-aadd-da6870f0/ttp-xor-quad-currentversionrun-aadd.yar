rule TTP_XOR_QUAD_CurrentVersionRun_aadd {
  strings:
    $key_aadd = { f9 b2 [2] dd bc [2] f6 90 [2] d8 b2 [2] cc a9 [2] c3 b3 [2] dd ae [2] df af [2] c4 a9 [2] d8 ae [2] c4 81 }

  condition:
    any of them
}