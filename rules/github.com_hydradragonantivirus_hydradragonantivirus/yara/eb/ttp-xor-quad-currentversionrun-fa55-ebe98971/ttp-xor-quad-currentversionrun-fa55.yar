rule TTP_XOR_QUAD_CurrentVersionRun_fa55 {
  strings:
    $key_fa55 = { a9 3a [2] 8d 34 [2] a6 18 [2] 88 3a [2] 9c 21 [2] 93 3b [2] 8d 26 [2] 8f 27 [2] 94 21 [2] 88 26 [2] 94 09 }

  condition:
    any of them
}