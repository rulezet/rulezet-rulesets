rule TTP_XOR_QUAD_CurrentVersionRun_3ef2 {
  strings:
    $key_3ef2 = { 6d 9d [2] 49 93 [2] 62 bf [2] 4c 9d [2] 58 86 [2] 57 9c [2] 49 81 [2] 4b 80 [2] 50 86 [2] 4c 81 [2] 50 ae }

  condition:
    any of them
}