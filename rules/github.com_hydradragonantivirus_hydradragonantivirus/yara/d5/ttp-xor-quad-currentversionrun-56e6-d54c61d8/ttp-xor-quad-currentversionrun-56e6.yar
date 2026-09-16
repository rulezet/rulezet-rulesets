rule TTP_XOR_QUAD_CurrentVersionRun_56e6 {
  strings:
    $key_56e6 = { 05 89 [2] 21 87 [2] 0a ab [2] 24 89 [2] 30 92 [2] 3f 88 [2] 21 95 [2] 23 94 [2] 38 92 [2] 24 95 [2] 38 ba }

  condition:
    any of them
}