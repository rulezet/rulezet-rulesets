rule TTP_XOR_QUAD_CurrentVersionRun_f5f2 {
  strings:
    $key_f5f2 = { a6 9d [2] 82 93 [2] a9 bf [2] 87 9d [2] 93 86 [2] 9c 9c [2] 82 81 [2] 80 80 [2] 9b 86 [2] 87 81 [2] 9b ae }

  condition:
    any of them
}