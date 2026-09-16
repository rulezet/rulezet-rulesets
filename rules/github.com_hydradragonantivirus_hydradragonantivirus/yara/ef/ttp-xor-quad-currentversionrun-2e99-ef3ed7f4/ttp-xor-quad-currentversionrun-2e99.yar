rule TTP_XOR_QUAD_CurrentVersionRun_2e99 {
  strings:
    $key_2e99 = { 7d f6 [2] 59 f8 [2] 72 d4 [2] 5c f6 [2] 48 ed [2] 47 f7 [2] 59 ea [2] 5b eb [2] 40 ed [2] 5c ea [2] 40 c5 }

  condition:
    any of them
}