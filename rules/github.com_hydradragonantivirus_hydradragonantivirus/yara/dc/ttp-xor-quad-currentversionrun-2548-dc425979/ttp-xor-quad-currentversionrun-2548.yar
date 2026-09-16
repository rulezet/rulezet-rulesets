rule TTP_XOR_QUAD_CurrentVersionRun_2548 {
  strings:
    $key_2548 = { 76 27 [2] 52 29 [2] 79 05 [2] 57 27 [2] 43 3c [2] 4c 26 [2] 52 3b [2] 50 3a [2] 4b 3c [2] 57 3b [2] 4b 14 }

  condition:
    any of them
}