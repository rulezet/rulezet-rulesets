rule TTP_XOR_QUAD_CurrentVersionRun_1ef2 {
  strings:
    $key_1ef2 = { 4d 9d [2] 69 93 [2] 42 bf [2] 6c 9d [2] 78 86 [2] 77 9c [2] 69 81 [2] 6b 80 [2] 70 86 [2] 6c 81 [2] 70 ae }

  condition:
    any of them
}