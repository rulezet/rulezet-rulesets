rule TTP_XOR_QUAD_CurrentVersionRun_f2cc {
  strings:
    $key_f2cc = { a1 a3 [2] 85 ad [2] ae 81 [2] 80 a3 [2] 94 b8 [2] 9b a2 [2] 85 bf [2] 87 be [2] 9c b8 [2] 80 bf [2] 9c 90 }

  condition:
    any of them
}