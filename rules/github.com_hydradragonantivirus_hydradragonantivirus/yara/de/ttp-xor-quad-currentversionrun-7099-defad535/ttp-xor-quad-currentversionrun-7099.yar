rule TTP_XOR_QUAD_CurrentVersionRun_7099 {
  strings:
    $key_7099 = { 23 f6 [2] 07 f8 [2] 2c d4 [2] 02 f6 [2] 16 ed [2] 19 f7 [2] 07 ea [2] 05 eb [2] 1e ed [2] 02 ea [2] 1e c5 }

  condition:
    any of them
}