rule TTP_XOR_QUAD_CurrentVersionRun_1742 {
  strings:
    $key_1742 = { 44 2d [2] 60 23 [2] 4b 0f [2] 65 2d [2] 71 36 [2] 7e 2c [2] 60 31 [2] 62 30 [2] 79 36 [2] 65 31 [2] 79 1e }

  condition:
    any of them
}