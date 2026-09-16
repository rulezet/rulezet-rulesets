rule TTP_XOR_QUAD_CurrentVersionRun_46e6 {
  strings:
    $key_46e6 = { 15 89 [2] 31 87 [2] 1a ab [2] 34 89 [2] 20 92 [2] 2f 88 [2] 31 95 [2] 33 94 [2] 28 92 [2] 34 95 [2] 28 ba }

  condition:
    any of them
}