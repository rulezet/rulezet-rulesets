rule TTP_XOR_QUAD_CurrentVersionRun_0fcc {
  strings:
    $key_0fcc = { 5c a3 [2] 78 ad [2] 53 81 [2] 7d a3 [2] 69 b8 [2] 66 a2 [2] 78 bf [2] 7a be [2] 61 b8 [2] 7d bf [2] 61 90 }

  condition:
    any of them
}