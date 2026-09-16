rule TTP_XOR_QUAD_CurrentVersionRun_7918 {
  strings:
    $key_7918 = { 2a 77 [2] 0e 79 [2] 25 55 [2] 0b 77 [2] 1f 6c [2] 10 76 [2] 0e 6b [2] 0c 6a [2] 17 6c [2] 0b 6b [2] 17 44 }

  condition:
    any of them
}