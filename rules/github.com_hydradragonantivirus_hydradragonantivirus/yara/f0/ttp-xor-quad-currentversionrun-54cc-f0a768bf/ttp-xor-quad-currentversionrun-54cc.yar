rule TTP_XOR_QUAD_CurrentVersionRun_54cc {
  strings:
    $key_54cc = { 07 a3 [2] 23 ad [2] 08 81 [2] 26 a3 [2] 32 b8 [2] 3d a2 [2] 23 bf [2] 21 be [2] 3a b8 [2] 26 bf [2] 3a 90 }

  condition:
    any of them
}