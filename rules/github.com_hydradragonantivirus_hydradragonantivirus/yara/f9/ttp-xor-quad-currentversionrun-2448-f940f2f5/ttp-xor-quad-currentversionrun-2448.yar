rule TTP_XOR_QUAD_CurrentVersionRun_2448 {
  strings:
    $key_2448 = { 77 27 [2] 53 29 [2] 78 05 [2] 56 27 [2] 42 3c [2] 4d 26 [2] 53 3b [2] 51 3a [2] 4a 3c [2] 56 3b [2] 4a 14 }

  condition:
    any of them
}