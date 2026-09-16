rule TTP_XOR_QUAD_CurrentVersionRun_60f2 {
  strings:
    $key_60f2 = { 33 9d [2] 17 93 [2] 3c bf [2] 12 9d [2] 06 86 [2] 09 9c [2] 17 81 [2] 15 80 [2] 0e 86 [2] 12 81 [2] 0e ae }

  condition:
    any of them
}