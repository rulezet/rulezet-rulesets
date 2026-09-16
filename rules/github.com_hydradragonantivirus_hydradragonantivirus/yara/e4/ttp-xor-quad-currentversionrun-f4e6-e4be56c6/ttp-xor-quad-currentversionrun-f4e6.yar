rule TTP_XOR_QUAD_CurrentVersionRun_f4e6 {
  strings:
    $key_f4e6 = { a7 89 [2] 83 87 [2] a8 ab [2] 86 89 [2] 92 92 [2] 9d 88 [2] 83 95 [2] 81 94 [2] 9a 92 [2] 86 95 [2] 9a ba }

  condition:
    any of them
}