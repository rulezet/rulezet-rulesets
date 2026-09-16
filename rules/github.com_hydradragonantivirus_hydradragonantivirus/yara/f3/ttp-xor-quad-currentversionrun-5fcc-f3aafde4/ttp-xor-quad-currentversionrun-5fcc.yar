rule TTP_XOR_QUAD_CurrentVersionRun_5fcc {
  strings:
    $key_5fcc = { 0c a3 [2] 28 ad [2] 03 81 [2] 2d a3 [2] 39 b8 [2] 36 a2 [2] 28 bf [2] 2a be [2] 31 b8 [2] 2d bf [2] 31 90 }

  condition:
    any of them
}