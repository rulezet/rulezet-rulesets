rule TTP_XOR_QUAD_CurrentVersionRun_67f2 {
  strings:
    $key_67f2 = { 34 9d [2] 10 93 [2] 3b bf [2] 15 9d [2] 01 86 [2] 0e 9c [2] 10 81 [2] 12 80 [2] 09 86 [2] 15 81 [2] 09 ae }

  condition:
    any of them
}