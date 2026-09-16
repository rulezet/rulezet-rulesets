rule TTP_XOR_QUAD_CurrentVersionRun_fa59 {
  strings:
    $key_fa59 = { a9 36 [2] 8d 38 [2] a6 14 [2] 88 36 [2] 9c 2d [2] 93 37 [2] 8d 2a [2] 8f 2b [2] 94 2d [2] 88 2a [2] 94 05 }

  condition:
    any of them
}