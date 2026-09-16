rule TTP_XOR_QUAD_CurrentVersionRun_30cc {
  strings:
    $key_30cc = { 63 a3 [2] 47 ad [2] 6c 81 [2] 42 a3 [2] 56 b8 [2] 59 a2 [2] 47 bf [2] 45 be [2] 5e b8 [2] 42 bf [2] 5e 90 }

  condition:
    any of them
}