rule TTP_XOR_QUAD_CurrentVersionRun_fa18 {
  strings:
    $key_fa18 = { a9 77 [2] 8d 79 [2] a6 55 [2] 88 77 [2] 9c 6c [2] 93 76 [2] 8d 6b [2] 8f 6a [2] 94 6c [2] 88 6b [2] 94 44 }

  condition:
    any of them
}