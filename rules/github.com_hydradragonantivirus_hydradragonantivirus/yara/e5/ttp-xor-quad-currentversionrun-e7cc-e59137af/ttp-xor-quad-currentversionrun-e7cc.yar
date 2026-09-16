rule TTP_XOR_QUAD_CurrentVersionRun_e7cc {
  strings:
    $key_e7cc = { b4 a3 [2] 90 ad [2] bb 81 [2] 95 a3 [2] 81 b8 [2] 8e a2 [2] 90 bf [2] 92 be [2] 89 b8 [2] 95 bf [2] 89 90 }

  condition:
    any of them
}