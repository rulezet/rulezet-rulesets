rule TTP_XOR_QUAD_CurrentVersionRun_6de6 {
  strings:
    $key_6de6 = { 3e 89 [2] 1a 87 [2] 31 ab [2] 1f 89 [2] 0b 92 [2] 04 88 [2] 1a 95 [2] 18 94 [2] 03 92 [2] 1f 95 [2] 03 ba }

  condition:
    any of them
}