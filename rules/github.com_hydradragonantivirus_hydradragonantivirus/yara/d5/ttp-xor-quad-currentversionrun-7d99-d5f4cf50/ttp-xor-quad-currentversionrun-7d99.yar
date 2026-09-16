rule TTP_XOR_QUAD_CurrentVersionRun_7d99 {
  strings:
    $key_7d99 = { 2e f6 [2] 0a f8 [2] 21 d4 [2] 0f f6 [2] 1b ed [2] 14 f7 [2] 0a ea [2] 08 eb [2] 13 ed [2] 0f ea [2] 13 c5 }

  condition:
    any of them
}