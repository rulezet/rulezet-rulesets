rule TTP_XOR_QUAD_CurrentVersionRun_1366 {
  strings:
    $key_1366 = { 40 09 [2] 64 07 [2] 4f 2b [2] 61 09 [2] 75 12 [2] 7a 08 [2] 64 15 [2] 66 14 [2] 7d 12 [2] 61 15 [2] 7d 3a }

  condition:
    any of them
}