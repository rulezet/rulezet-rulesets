rule TTP_XOR_QUAD_CurrentVersionRun_6318 {
  strings:
    $key_6318 = { 30 77 [2] 14 79 [2] 3f 55 [2] 11 77 [2] 05 6c [2] 0a 76 [2] 14 6b [2] 16 6a [2] 0d 6c [2] 11 6b [2] 0d 44 }

  condition:
    any of them
}