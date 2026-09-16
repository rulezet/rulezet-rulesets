rule TTP_XOR_QUAD_CurrentVersionRun_4699 {
  strings:
    $key_4699 = { 15 f6 [2] 31 f8 [2] 1a d4 [2] 34 f6 [2] 20 ed [2] 2f f7 [2] 31 ea [2] 33 eb [2] 28 ed [2] 34 ea [2] 28 c5 }

  condition:
    any of them
}