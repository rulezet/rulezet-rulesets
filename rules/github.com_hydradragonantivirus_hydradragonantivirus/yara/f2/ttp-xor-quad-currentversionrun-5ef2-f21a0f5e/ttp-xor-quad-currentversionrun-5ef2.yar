rule TTP_XOR_QUAD_CurrentVersionRun_5ef2 {
  strings:
    $key_5ef2 = { 0d 9d [2] 29 93 [2] 02 bf [2] 2c 9d [2] 38 86 [2] 37 9c [2] 29 81 [2] 2b 80 [2] 30 86 [2] 2c 81 [2] 30 ae }

  condition:
    any of them
}