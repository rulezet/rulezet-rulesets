rule TTP_XOR_QUAD_CurrentVersionRun_2a08 {
  strings:
    $key_2a08 = { 79 67 [2] 5d 69 [2] 76 45 [2] 58 67 [2] 4c 7c [2] 43 66 [2] 5d 7b [2] 5f 7a [2] 44 7c [2] 58 7b [2] 44 54 }

  condition:
    any of them
}