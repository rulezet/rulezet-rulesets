rule TTP_XOR_QUAD_CurrentVersionRun_36cc {
  strings:
    $key_36cc = { 65 a3 [2] 41 ad [2] 6a 81 [2] 44 a3 [2] 50 b8 [2] 5f a2 [2] 41 bf [2] 43 be [2] 58 b8 [2] 44 bf [2] 58 90 }

  condition:
    any of them
}