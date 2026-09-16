rule TTP_XOR_QUAD_CurrentVersionRun_2a09 {
  strings:
    $key_2a09 = { 79 66 [2] 5d 68 [2] 76 44 [2] 58 66 [2] 4c 7d [2] 43 67 [2] 5d 7a [2] 5f 7b [2] 44 7d [2] 58 7a [2] 44 55 }

  condition:
    any of them
}