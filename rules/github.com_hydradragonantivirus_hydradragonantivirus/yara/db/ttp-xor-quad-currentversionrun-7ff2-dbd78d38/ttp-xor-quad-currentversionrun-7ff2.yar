rule TTP_XOR_QUAD_CurrentVersionRun_7ff2 {
  strings:
    $key_7ff2 = { 2c 9d [2] 08 93 [2] 23 bf [2] 0d 9d [2] 19 86 [2] 16 9c [2] 08 81 [2] 0a 80 [2] 11 86 [2] 0d 81 [2] 11 ae }

  condition:
    any of them
}