rule TTP_XOR_QUAD_CurrentVersionRun_24d1 {
  strings:
    $key_24d1 = { 77 be [2] 53 b0 [2] 78 9c [2] 56 be [2] 42 a5 [2] 4d bf [2] 53 a2 [2] 51 a3 [2] 4a a5 [2] 56 a2 [2] 4a 8d }

  condition:
    any of them
}