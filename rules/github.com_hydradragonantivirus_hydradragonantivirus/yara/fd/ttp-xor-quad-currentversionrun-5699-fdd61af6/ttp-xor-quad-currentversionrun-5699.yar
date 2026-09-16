rule TTP_XOR_QUAD_CurrentVersionRun_5699 {
  strings:
    $key_5699 = { 05 f6 [2] 21 f8 [2] 0a d4 [2] 24 f6 [2] 30 ed [2] 3f f7 [2] 21 ea [2] 23 eb [2] 38 ed [2] 24 ea [2] 38 c5 }

  condition:
    any of them
}