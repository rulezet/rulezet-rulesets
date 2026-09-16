rule TTP_XOR_QUAD_CurrentVersionRun_2799 {
  strings:
    $key_2799 = { 74 f6 [2] 50 f8 [2] 7b d4 [2] 55 f6 [2] 41 ed [2] 4e f7 [2] 50 ea [2] 52 eb [2] 49 ed [2] 55 ea [2] 49 c5 }

  condition:
    any of them
}