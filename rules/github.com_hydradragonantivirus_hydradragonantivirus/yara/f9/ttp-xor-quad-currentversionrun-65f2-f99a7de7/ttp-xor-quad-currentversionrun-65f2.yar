rule TTP_XOR_QUAD_CurrentVersionRun_65f2 {
  strings:
    $key_65f2 = { 36 9d [2] 12 93 [2] 39 bf [2] 17 9d [2] 03 86 [2] 0c 9c [2] 12 81 [2] 10 80 [2] 0b 86 [2] 17 81 [2] 0b ae }

  condition:
    any of them
}