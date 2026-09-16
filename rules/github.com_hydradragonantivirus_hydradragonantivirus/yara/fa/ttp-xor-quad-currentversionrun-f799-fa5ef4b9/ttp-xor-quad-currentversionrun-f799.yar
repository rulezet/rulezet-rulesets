rule TTP_XOR_QUAD_CurrentVersionRun_f799 {
  strings:
    $key_f799 = { a4 f6 [2] 80 f8 [2] ab d4 [2] 85 f6 [2] 91 ed [2] 9e f7 [2] 80 ea [2] 82 eb [2] 99 ed [2] 85 ea [2] 99 c5 }

  condition:
    any of them
}