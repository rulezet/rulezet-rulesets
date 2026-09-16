rule TTP_XOR_QUAD_CurrentVersionRun_6099 {
  strings:
    $key_6099 = { 33 f6 [2] 17 f8 [2] 3c d4 [2] 12 f6 [2] 06 ed [2] 09 f7 [2] 17 ea [2] 15 eb [2] 0e ed [2] 12 ea [2] 0e c5 }

  condition:
    any of them
}