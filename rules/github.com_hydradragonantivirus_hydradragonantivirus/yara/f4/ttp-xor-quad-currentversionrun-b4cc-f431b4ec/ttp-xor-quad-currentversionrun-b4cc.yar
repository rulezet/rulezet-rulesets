rule TTP_XOR_QUAD_CurrentVersionRun_b4cc {
  strings:
    $key_b4cc = { e7 a3 [2] c3 ad [2] e8 81 [2] c6 a3 [2] d2 b8 [2] dd a2 [2] c3 bf [2] c1 be [2] da b8 [2] c6 bf [2] da 90 }

  condition:
    any of them
}