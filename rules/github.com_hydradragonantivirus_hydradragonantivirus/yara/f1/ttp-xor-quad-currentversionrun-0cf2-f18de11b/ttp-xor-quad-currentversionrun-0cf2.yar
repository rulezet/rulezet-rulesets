rule TTP_XOR_QUAD_CurrentVersionRun_0cf2 {
  strings:
    $key_0cf2 = { 5f 9d [2] 7b 93 [2] 50 bf [2] 7e 9d [2] 6a 86 [2] 65 9c [2] 7b 81 [2] 79 80 [2] 62 86 [2] 7e 81 [2] 62 ae }

  condition:
    any of them
}