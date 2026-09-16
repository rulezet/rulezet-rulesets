rule TTP_XOR_QUAD_CurrentVersionRun_2f18 {
  strings:
    $key_2f18 = { 7c 77 [2] 58 79 [2] 73 55 [2] 5d 77 [2] 49 6c [2] 46 76 [2] 58 6b [2] 5a 6a [2] 41 6c [2] 5d 6b [2] 41 44 }

  condition:
    any of them
}