rule TTP_XOR_QUAD_CurrentVersionRun_2a39 {
  strings:
    $key_2a39 = { 79 56 [2] 5d 58 [2] 76 74 [2] 58 56 [2] 4c 4d [2] 43 57 [2] 5d 4a [2] 5f 4b [2] 44 4d [2] 58 4a [2] 44 65 }

  condition:
    any of them
}