rule TTP_XOR_QUAD_CurrentVersionRun_4ce6 {
  strings:
    $key_4ce6 = { 1f 89 [2] 3b 87 [2] 10 ab [2] 3e 89 [2] 2a 92 [2] 25 88 [2] 3b 95 [2] 39 94 [2] 22 92 [2] 3e 95 [2] 22 ba }

  condition:
    any of them
}