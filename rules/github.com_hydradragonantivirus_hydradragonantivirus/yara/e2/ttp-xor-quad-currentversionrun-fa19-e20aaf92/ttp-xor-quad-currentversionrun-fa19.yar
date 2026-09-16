rule TTP_XOR_QUAD_CurrentVersionRun_fa19 {
  strings:
    $key_fa19 = { a9 76 [2] 8d 78 [2] a6 54 [2] 88 76 [2] 9c 6d [2] 93 77 [2] 8d 6a [2] 8f 6b [2] 94 6d [2] 88 6a [2] 94 45 }

  condition:
    any of them
}