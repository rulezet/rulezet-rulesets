rule TTP_XOR_QUAD_CurrentVersionRun_2099 {
  strings:
    $key_2099 = { 73 f6 [2] 57 f8 [2] 7c d4 [2] 52 f6 [2] 46 ed [2] 49 f7 [2] 57 ea [2] 55 eb [2] 4e ed [2] 52 ea [2] 4e c5 }

  condition:
    any of them
}