rule TTP_XOR_QUAD_CurrentVersionRun_17e6 {
  strings:
    $key_17e6 = { 44 89 [2] 60 87 [2] 4b ab [2] 65 89 [2] 71 92 [2] 7e 88 [2] 60 95 [2] 62 94 [2] 79 92 [2] 65 95 [2] 79 ba }

  condition:
    any of them
}