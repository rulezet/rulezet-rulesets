rule TTP_XOR_QUAD_CurrentVersionRun_2a19 {
  strings:
    $key_2a19 = { 79 76 [2] 5d 78 [2] 76 54 [2] 58 76 [2] 4c 6d [2] 43 77 [2] 5d 6a [2] 5f 6b [2] 44 6d [2] 58 6a [2] 44 45 }

  condition:
    any of them
}