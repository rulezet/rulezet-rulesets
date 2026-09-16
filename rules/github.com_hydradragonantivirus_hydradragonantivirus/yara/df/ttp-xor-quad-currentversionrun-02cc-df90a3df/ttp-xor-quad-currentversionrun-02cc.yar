rule TTP_XOR_QUAD_CurrentVersionRun_02cc {
  strings:
    $key_02cc = { 51 a3 [2] 75 ad [2] 5e 81 [2] 70 a3 [2] 64 b8 [2] 6b a2 [2] 75 bf [2] 77 be [2] 6c b8 [2] 70 bf [2] 6c 90 }

  condition:
    any of them
}