rule TTP_XOR_QUAD_CurrentVersionRun_45cc {
  strings:
    $key_45cc = { 16 a3 [2] 32 ad [2] 19 81 [2] 37 a3 [2] 23 b8 [2] 2c a2 [2] 32 bf [2] 30 be [2] 2b b8 [2] 37 bf [2] 2b 90 }

  condition:
    any of them
}