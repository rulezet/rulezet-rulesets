rule TTP_XOR_QUAD_CurrentVersionRun_1f2c {
  strings:
    $key_1f2c = { 4c 43 [2] 68 4d [2] 43 61 [2] 6d 43 [2] 79 58 [2] 76 42 [2] 68 5f [2] 6a 5e [2] 71 58 [2] 6d 5f [2] 71 70 }

  condition:
    any of them
}