rule TTP_XOR_QUAD_CurrentVersionRun_e799 {
  strings:
    $key_e799 = { b4 f6 [2] 90 f8 [2] bb d4 [2] 95 f6 [2] 81 ed [2] 8e f7 [2] 90 ea [2] 92 eb [2] 89 ed [2] 95 ea [2] 89 c5 }

  condition:
    any of them
}