rule TTP_XOR_QUAD_CurrentVersionRun_2318 {
  strings:
    $key_2318 = { 70 77 [2] 54 79 [2] 7f 55 [2] 51 77 [2] 45 6c [2] 4a 76 [2] 54 6b [2] 56 6a [2] 4d 6c [2] 51 6b [2] 4d 44 }

  condition:
    any of them
}