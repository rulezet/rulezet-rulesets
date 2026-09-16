rule TTP_XOR_QUAD_CurrentVersionRun_3be6 {
  strings:
    $key_3be6 = { 68 89 [2] 4c 87 [2] 67 ab [2] 49 89 [2] 5d 92 [2] 52 88 [2] 4c 95 [2] 4e 94 [2] 55 92 [2] 49 95 [2] 55 ba }

  condition:
    any of them
}