rule TTP_XOR_QUAD_CurrentVersionRun_31cc {
  strings:
    $key_31cc = { 62 a3 [2] 46 ad [2] 6d 81 [2] 43 a3 [2] 57 b8 [2] 58 a2 [2] 46 bf [2] 44 be [2] 5f b8 [2] 43 bf [2] 5f 90 }

  condition:
    any of them
}