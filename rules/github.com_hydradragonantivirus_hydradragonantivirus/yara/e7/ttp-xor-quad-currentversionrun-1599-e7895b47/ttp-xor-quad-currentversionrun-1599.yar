rule TTP_XOR_QUAD_CurrentVersionRun_1599 {
  strings:
    $key_1599 = { 46 f6 [2] 62 f8 [2] 49 d4 [2] 67 f6 [2] 73 ed [2] 7c f7 [2] 62 ea [2] 60 eb [2] 7b ed [2] 67 ea [2] 7b c5 }

  condition:
    any of them
}