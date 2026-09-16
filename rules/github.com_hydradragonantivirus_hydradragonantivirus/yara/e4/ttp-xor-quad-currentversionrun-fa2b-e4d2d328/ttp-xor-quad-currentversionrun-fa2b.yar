rule TTP_XOR_QUAD_CurrentVersionRun_fa2b {
  strings:
    $key_fa2b = { a9 44 [2] 8d 4a [2] a6 66 [2] 88 44 [2] 9c 5f [2] 93 45 [2] 8d 58 [2] 8f 59 [2] 94 5f [2] 88 58 [2] 94 77 }

  condition:
    any of them
}