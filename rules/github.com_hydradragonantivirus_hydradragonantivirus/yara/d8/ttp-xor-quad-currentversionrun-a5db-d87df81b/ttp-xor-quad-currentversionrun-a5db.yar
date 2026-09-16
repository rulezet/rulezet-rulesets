rule TTP_XOR_QUAD_CurrentVersionRun_a5db {
  strings:
    $key_a5db = { f6 b4 [2] d2 ba [2] f9 96 [2] d7 b4 [2] c3 af [2] cc b5 [2] d2 a8 [2] d0 a9 [2] cb af [2] d7 a8 [2] cb 87 }

  condition:
    any of them
}