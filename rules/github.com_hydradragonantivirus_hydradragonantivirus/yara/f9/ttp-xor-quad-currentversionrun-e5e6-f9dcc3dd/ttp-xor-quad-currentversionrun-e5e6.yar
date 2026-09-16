rule TTP_XOR_QUAD_CurrentVersionRun_e5e6 {
  strings:
    $key_e5e6 = { b6 89 [2] 92 87 [2] b9 ab [2] 97 89 [2] 83 92 [2] 8c 88 [2] 92 95 [2] 90 94 [2] 8b 92 [2] 97 95 [2] 8b ba }

  condition:
    any of them
}