rule TTP_XOR_QUAD_CurrentVersionRun_78f2 {
  strings:
    $key_78f2 = { 2b 9d [2] 0f 93 [2] 24 bf [2] 0a 9d [2] 1e 86 [2] 11 9c [2] 0f 81 [2] 0d 80 [2] 16 86 [2] 0a 81 [2] 16 ae }

  condition:
    any of them
}