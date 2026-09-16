rule TTP_XOR_QUAD_CurrentVersionRun_04f2 {
  strings:
    $key_04f2 = { 57 9d [2] 73 93 [2] 58 bf [2] 76 9d [2] 62 86 [2] 6d 9c [2] 73 81 [2] 71 80 [2] 6a 86 [2] 76 81 [2] 6a ae }

  condition:
    any of them
}