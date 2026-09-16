rule TTP_XOR_QUAD_CurrentVersionRun_6fcc {
  strings:
    $key_6fcc = { 3c a3 [2] 18 ad [2] 33 81 [2] 1d a3 [2] 09 b8 [2] 06 a2 [2] 18 bf [2] 1a be [2] 01 b8 [2] 1d bf [2] 01 90 }

  condition:
    any of them
}