rule TTP_XOR_QUAD_CurrentVersionRun_02d1 {
  strings:
    $key_02d1 = { 51 be [2] 75 b0 [2] 5e 9c [2] 70 be [2] 64 a5 [2] 6b bf [2] 75 a2 [2] 77 a3 [2] 6c a5 [2] 70 a2 [2] 6c 8d }

  condition:
    any of them
}