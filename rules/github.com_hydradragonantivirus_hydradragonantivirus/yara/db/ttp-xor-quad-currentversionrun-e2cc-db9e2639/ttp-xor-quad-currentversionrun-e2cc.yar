rule TTP_XOR_QUAD_CurrentVersionRun_e2cc {
  strings:
    $key_e2cc = { b1 a3 [2] 95 ad [2] be 81 [2] 90 a3 [2] 84 b8 [2] 8b a2 [2] 95 bf [2] 97 be [2] 8c b8 [2] 90 bf [2] 8c 90 }

  condition:
    any of them
}