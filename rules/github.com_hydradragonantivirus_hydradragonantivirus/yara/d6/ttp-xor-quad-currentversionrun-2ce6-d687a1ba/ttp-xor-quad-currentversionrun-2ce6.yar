rule TTP_XOR_QUAD_CurrentVersionRun_2ce6 {
  strings:
    $key_2ce6 = { 7f 89 [2] 5b 87 [2] 70 ab [2] 5e 89 [2] 4a 92 [2] 45 88 [2] 5b 95 [2] 59 94 [2] 42 92 [2] 5e 95 [2] 42 ba }

  condition:
    any of them
}