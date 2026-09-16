rule TTP_XOR_QUAD_CurrentVersionRun_1663 {
  strings:
    $key_1663 = { 45 0c [2] 61 02 [2] 4a 2e [2] 64 0c [2] 70 17 [2] 7f 0d [2] 61 10 [2] 63 11 [2] 78 17 [2] 64 10 [2] 78 3f }

  condition:
    any of them
}