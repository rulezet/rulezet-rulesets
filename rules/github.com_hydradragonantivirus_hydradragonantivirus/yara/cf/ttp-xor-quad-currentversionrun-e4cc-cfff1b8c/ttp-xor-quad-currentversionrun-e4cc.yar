rule TTP_XOR_QUAD_CurrentVersionRun_e4cc {
  strings:
    $key_e4cc = { b7 a3 [2] 93 ad [2] b8 81 [2] 96 a3 [2] 82 b8 [2] 8d a2 [2] 93 bf [2] 91 be [2] 8a b8 [2] 96 bf [2] 8a 90 }

  condition:
    any of them
}