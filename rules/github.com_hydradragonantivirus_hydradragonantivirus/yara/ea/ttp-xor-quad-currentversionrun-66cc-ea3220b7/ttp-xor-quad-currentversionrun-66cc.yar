rule TTP_XOR_QUAD_CurrentVersionRun_66cc {
  strings:
    $key_66cc = { 35 a3 [2] 11 ad [2] 3a 81 [2] 14 a3 [2] 00 b8 [2] 0f a2 [2] 11 bf [2] 13 be [2] 08 b8 [2] 14 bf [2] 08 90 }

  condition:
    any of them
}