rule TTP_XOR_QUAD_CurrentVersionRun_1363 {
  strings:
    $key_1363 = { 40 0c [2] 64 02 [2] 4f 2e [2] 61 0c [2] 75 17 [2] 7a 0d [2] 64 10 [2] 66 11 [2] 7d 17 [2] 61 10 [2] 7d 3f }

  condition:
    any of them
}