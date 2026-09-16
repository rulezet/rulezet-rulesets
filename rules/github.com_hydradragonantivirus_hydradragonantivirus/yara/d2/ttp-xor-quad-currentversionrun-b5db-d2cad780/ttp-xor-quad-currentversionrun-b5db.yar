rule TTP_XOR_QUAD_CurrentVersionRun_b5db {
  strings:
    $key_b5db = { e6 b4 [2] c2 ba [2] e9 96 [2] c7 b4 [2] d3 af [2] dc b5 [2] c2 a8 [2] c0 a9 [2] db af [2] c7 a8 [2] db 87 }

  condition:
    any of them
}