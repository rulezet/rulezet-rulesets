rule TTP_XOR_QUAD_CurrentVersionRun_79f2 {
  strings:
    $key_79f2 = { 2a 9d [2] 0e 93 [2] 25 bf [2] 0b 9d [2] 1f 86 [2] 10 9c [2] 0e 81 [2] 0c 80 [2] 17 86 [2] 0b 81 [2] 17 ae }

  condition:
    any of them
}