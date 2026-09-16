rule TTP_XOR_QUAD_CurrentVersionRun_65cc {
  strings:
    $key_65cc = { 36 a3 [2] 12 ad [2] 39 81 [2] 17 a3 [2] 03 b8 [2] 0c a2 [2] 12 bf [2] 10 be [2] 0b b8 [2] 17 bf [2] 0b 90 }

  condition:
    any of them
}