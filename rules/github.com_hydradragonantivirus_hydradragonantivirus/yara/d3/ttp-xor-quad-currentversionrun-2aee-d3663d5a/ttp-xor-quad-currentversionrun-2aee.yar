rule TTP_XOR_QUAD_CurrentVersionRun_2aee {
  strings:
    $key_2aee = { 79 81 [2] 5d 8f [2] 76 a3 [2] 58 81 [2] 4c 9a [2] 43 80 [2] 5d 9d [2] 5f 9c [2] 44 9a [2] 58 9d [2] 44 b2 }

  condition:
    any of them
}