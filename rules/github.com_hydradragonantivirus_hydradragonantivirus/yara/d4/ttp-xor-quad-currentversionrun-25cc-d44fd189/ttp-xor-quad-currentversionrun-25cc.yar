rule TTP_XOR_QUAD_CurrentVersionRun_25cc {
  strings:
    $key_25cc = { 76 a3 [2] 52 ad [2] 79 81 [2] 57 a3 [2] 43 b8 [2] 4c a2 [2] 52 bf [2] 50 be [2] 4b b8 [2] 57 bf [2] 4b 90 }

  condition:
    any of them
}