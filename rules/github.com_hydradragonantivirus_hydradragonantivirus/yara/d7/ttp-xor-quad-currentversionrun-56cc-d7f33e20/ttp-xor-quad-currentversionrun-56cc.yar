rule TTP_XOR_QUAD_CurrentVersionRun_56cc {
  strings:
    $key_56cc = { 05 a3 [2] 21 ad [2] 0a 81 [2] 24 a3 [2] 30 b8 [2] 3f a2 [2] 21 bf [2] 23 be [2] 38 b8 [2] 24 bf [2] 38 90 }

  condition:
    any of them
}