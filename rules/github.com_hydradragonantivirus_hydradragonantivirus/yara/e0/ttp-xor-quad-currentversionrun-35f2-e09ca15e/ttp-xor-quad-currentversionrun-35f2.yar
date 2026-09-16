rule TTP_XOR_QUAD_CurrentVersionRun_35f2 {
  strings:
    $key_35f2 = { 66 9d [2] 42 93 [2] 69 bf [2] 47 9d [2] 53 86 [2] 5c 9c [2] 42 81 [2] 40 80 [2] 5b 86 [2] 47 81 [2] 5b ae }

  condition:
    any of them
}