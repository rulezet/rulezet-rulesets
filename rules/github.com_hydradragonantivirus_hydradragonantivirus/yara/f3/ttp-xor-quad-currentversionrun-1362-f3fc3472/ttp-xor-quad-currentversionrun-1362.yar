rule TTP_XOR_QUAD_CurrentVersionRun_1362 {
  strings:
    $key_1362 = { 40 0d [2] 64 03 [2] 4f 2f [2] 61 0d [2] 75 16 [2] 7a 0c [2] 64 11 [2] 66 10 [2] 7d 16 [2] 61 11 [2] 7d 3e }

  condition:
    any of them
}