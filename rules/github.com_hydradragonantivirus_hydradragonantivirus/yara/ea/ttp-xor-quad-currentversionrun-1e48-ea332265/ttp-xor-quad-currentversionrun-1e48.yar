rule TTP_XOR_QUAD_CurrentVersionRun_1e48 {
  strings:
    $key_1e48 = { 4d 27 [2] 69 29 [2] 42 05 [2] 6c 27 [2] 78 3c [2] 77 26 [2] 69 3b [2] 6b 3a [2] 70 3c [2] 6c 3b [2] 70 14 }

  condition:
    any of them
}