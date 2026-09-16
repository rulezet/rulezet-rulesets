rule TTP_XOR_QUAD_CurrentVersionRun_2ee6 {
  strings:
    $key_2ee6 = { 7d 89 [2] 59 87 [2] 72 ab [2] 5c 89 [2] 48 92 [2] 47 88 [2] 59 95 [2] 5b 94 [2] 40 92 [2] 5c 95 [2] 40 ba }

  condition:
    any of them
}