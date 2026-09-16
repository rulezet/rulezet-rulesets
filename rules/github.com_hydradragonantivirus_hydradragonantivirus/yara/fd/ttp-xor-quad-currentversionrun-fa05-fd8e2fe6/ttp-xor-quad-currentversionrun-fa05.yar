rule TTP_XOR_QUAD_CurrentVersionRun_fa05 {
  strings:
    $key_fa05 = { a9 6a [2] 8d 64 [2] a6 48 [2] 88 6a [2] 9c 71 [2] 93 6b [2] 8d 76 [2] 8f 77 [2] 94 71 [2] 88 76 [2] 94 59 }

  condition:
    any of them
}