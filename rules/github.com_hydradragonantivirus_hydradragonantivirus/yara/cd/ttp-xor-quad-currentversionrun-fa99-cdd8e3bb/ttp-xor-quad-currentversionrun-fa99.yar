rule TTP_XOR_QUAD_CurrentVersionRun_fa99 {
  strings:
    $key_fa99 = { a9 f6 [2] 8d f8 [2] a6 d4 [2] 88 f6 [2] 9c ed [2] 93 f7 [2] 8d ea [2] 8f eb [2] 94 ed [2] 88 ea [2] 94 c5 }

  condition:
    any of them
}