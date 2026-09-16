rule TTP_XOR_QUAD_CurrentVersionRun_1048 {
  strings:
    $key_1048 = { 43 27 [2] 67 29 [2] 4c 05 [2] 62 27 [2] 76 3c [2] 79 26 [2] 67 3b [2] 65 3a [2] 7e 3c [2] 62 3b [2] 7e 14 }

  condition:
    any of them
}