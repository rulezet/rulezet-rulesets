rule TTP_XOR_QUAD_CurrentVersionRun_fa48 {
  strings:
    $key_fa48 = { a9 27 [2] 8d 29 [2] a6 05 [2] 88 27 [2] 9c 3c [2] 93 26 [2] 8d 3b [2] 8f 3a [2] 94 3c [2] 88 3b [2] 94 14 }

  condition:
    any of them
}