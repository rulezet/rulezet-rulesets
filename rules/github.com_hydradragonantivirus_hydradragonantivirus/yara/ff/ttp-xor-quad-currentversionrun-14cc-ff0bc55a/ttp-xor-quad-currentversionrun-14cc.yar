rule TTP_XOR_QUAD_CurrentVersionRun_14cc {
  strings:
    $key_14cc = { 47 a3 [2] 63 ad [2] 48 81 [2] 66 a3 [2] 72 b8 [2] 7d a2 [2] 63 bf [2] 61 be [2] 7a b8 [2] 66 bf [2] 7a 90 }

  condition:
    any of them
}