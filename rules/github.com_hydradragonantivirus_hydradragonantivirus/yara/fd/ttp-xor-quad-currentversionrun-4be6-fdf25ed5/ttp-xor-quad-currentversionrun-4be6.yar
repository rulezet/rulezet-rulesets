rule TTP_XOR_QUAD_CurrentVersionRun_4be6 {
  strings:
    $key_4be6 = { 18 89 [2] 3c 87 [2] 17 ab [2] 39 89 [2] 2d 92 [2] 22 88 [2] 3c 95 [2] 3e 94 [2] 25 92 [2] 39 95 [2] 25 ba }

  condition:
    any of them
}