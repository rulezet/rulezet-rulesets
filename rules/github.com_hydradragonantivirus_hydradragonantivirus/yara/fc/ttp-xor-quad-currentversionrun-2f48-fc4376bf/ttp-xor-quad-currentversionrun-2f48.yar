rule TTP_XOR_QUAD_CurrentVersionRun_2f48 {
  strings:
    $key_2f48 = { 7c 27 [2] 58 29 [2] 73 05 [2] 5d 27 [2] 49 3c [2] 46 26 [2] 58 3b [2] 5a 3a [2] 41 3c [2] 5d 3b [2] 41 14 }

  condition:
    any of them
}