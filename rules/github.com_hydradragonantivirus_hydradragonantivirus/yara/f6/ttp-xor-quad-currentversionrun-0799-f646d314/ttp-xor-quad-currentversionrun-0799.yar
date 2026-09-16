rule TTP_XOR_QUAD_CurrentVersionRun_0799 {
  strings:
    $key_0799 = { 54 f6 [2] 70 f8 [2] 5b d4 [2] 75 f6 [2] 61 ed [2] 6e f7 [2] 70 ea [2] 72 eb [2] 69 ed [2] 75 ea [2] 69 c5 }

  condition:
    any of them
}