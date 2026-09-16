rule TTP_XOR_QUAD_CurrentVersionRun_f5cc {
  strings:
    $key_f5cc = { a6 a3 [2] 82 ad [2] a9 81 [2] 87 a3 [2] 93 b8 [2] 9c a2 [2] 82 bf [2] 80 be [2] 9b b8 [2] 87 bf [2] 9b 90 }

  condition:
    any of them
}