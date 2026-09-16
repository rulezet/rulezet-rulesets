rule TTP_XOR_QUAD_CurrentVersionRun_4799 {
  strings:
    $key_4799 = { 14 f6 [2] 30 f8 [2] 1b d4 [2] 35 f6 [2] 21 ed [2] 2e f7 [2] 30 ea [2] 32 eb [2] 29 ed [2] 35 ea [2] 29 c5 }

  condition:
    any of them
}