rule TTP_XOR_QUAD_CurrentVersionRun_1351 {
  strings:
    $key_1351 = { 40 3e [2] 64 30 [2] 4f 1c [2] 61 3e [2] 75 25 [2] 7a 3f [2] 64 22 [2] 66 23 [2] 7d 25 [2] 61 22 [2] 7d 0d }

  condition:
    any of them
}