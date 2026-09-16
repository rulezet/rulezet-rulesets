rule TTP_XOR_QUAD_CurrentVersionRun_44cc {
  strings:
    $key_44cc = { 17 a3 [2] 33 ad [2] 18 81 [2] 36 a3 [2] 22 b8 [2] 2d a2 [2] 33 bf [2] 31 be [2] 2a b8 [2] 36 bf [2] 2a 90 }

  condition:
    any of them
}