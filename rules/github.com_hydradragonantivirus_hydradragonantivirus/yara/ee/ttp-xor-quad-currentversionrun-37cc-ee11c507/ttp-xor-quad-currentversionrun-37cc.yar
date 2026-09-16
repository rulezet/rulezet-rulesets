rule TTP_XOR_QUAD_CurrentVersionRun_37cc {
  strings:
    $key_37cc = { 64 a3 [2] 40 ad [2] 6b 81 [2] 45 a3 [2] 51 b8 [2] 5e a2 [2] 40 bf [2] 42 be [2] 59 b8 [2] 45 bf [2] 59 90 }

  condition:
    any of them
}