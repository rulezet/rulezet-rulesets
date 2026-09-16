rule TTP_XOR_QUAD_CurrentVersionRun_3599 {
  strings:
    $key_3599 = { 66 f6 [2] 42 f8 [2] 69 d4 [2] 47 f6 [2] 53 ed [2] 5c f7 [2] 42 ea [2] 40 eb [2] 5b ed [2] 47 ea [2] 5b c5 }

  condition:
    any of them
}