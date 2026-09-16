rule TTP_XOR_QUAD_CurrentVersionRun_2d99 {
  strings:
    $key_2d99 = { 7e f6 [2] 5a f8 [2] 71 d4 [2] 5f f6 [2] 4b ed [2] 44 f7 [2] 5a ea [2] 58 eb [2] 43 ed [2] 5f ea [2] 43 c5 }

  condition:
    any of them
}