rule TTP_XOR_QUAD_CurrentVersionRun_7ef2 {
  strings:
    $key_7ef2 = { 2d 9d [2] 09 93 [2] 22 bf [2] 0c 9d [2] 18 86 [2] 17 9c [2] 09 81 [2] 0b 80 [2] 10 86 [2] 0c 81 [2] 10 ae }

  condition:
    any of them
}