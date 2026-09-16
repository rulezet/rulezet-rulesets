rule TTP_XOR_QUAD_CurrentVersionRun_0318 {
  strings:
    $key_0318 = { 50 77 [2] 74 79 [2] 5f 55 [2] 71 77 [2] 65 6c [2] 6a 76 [2] 74 6b [2] 76 6a [2] 6d 6c [2] 71 6b [2] 6d 44 }

  condition:
    any of them
}