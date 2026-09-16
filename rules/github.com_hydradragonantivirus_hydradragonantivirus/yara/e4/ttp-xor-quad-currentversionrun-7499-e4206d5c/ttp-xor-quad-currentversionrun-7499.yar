rule TTP_XOR_QUAD_CurrentVersionRun_7499 {
  strings:
    $key_7499 = { 27 f6 [2] 03 f8 [2] 28 d4 [2] 06 f6 [2] 12 ed [2] 1d f7 [2] 03 ea [2] 01 eb [2] 1a ed [2] 06 ea [2] 1a c5 }

  condition:
    any of them
}