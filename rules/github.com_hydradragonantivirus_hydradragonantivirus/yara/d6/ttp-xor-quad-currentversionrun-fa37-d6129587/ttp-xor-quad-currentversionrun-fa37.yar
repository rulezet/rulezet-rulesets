rule TTP_XOR_QUAD_CurrentVersionRun_fa37 {
  strings:
    $key_fa37 = { a9 58 [2] 8d 56 [2] a6 7a [2] 88 58 [2] 9c 43 [2] 93 59 [2] 8d 44 [2] 8f 45 [2] 94 43 [2] 88 44 [2] 94 6b }

  condition:
    any of them
}