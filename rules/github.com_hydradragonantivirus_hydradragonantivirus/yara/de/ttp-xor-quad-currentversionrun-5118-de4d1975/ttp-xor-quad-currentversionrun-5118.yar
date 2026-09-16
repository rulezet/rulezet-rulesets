rule TTP_XOR_QUAD_CurrentVersionRun_5118 {
  strings:
    $key_5118 = { 02 77 [2] 26 79 [2] 0d 55 [2] 23 77 [2] 37 6c [2] 38 76 [2] 26 6b [2] 24 6a [2] 3f 6c [2] 23 6b [2] 3f 44 }

  condition:
    any of them
}