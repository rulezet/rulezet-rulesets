rule TTP_XOR_QUAD_CurrentVersionRun_f6cc {
  strings:
    $key_f6cc = { a5 a3 [2] 81 ad [2] aa 81 [2] 84 a3 [2] 90 b8 [2] 9f a2 [2] 81 bf [2] 83 be [2] 98 b8 [2] 84 bf [2] 98 90 }

  condition:
    any of them
}