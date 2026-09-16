rule TTP_XOR_QUAD_CurrentVersionRun_7199 {
  strings:
    $key_7199 = { 22 f6 [2] 06 f8 [2] 2d d4 [2] 03 f6 [2] 17 ed [2] 18 f7 [2] 06 ea [2] 04 eb [2] 1f ed [2] 03 ea [2] 1f c5 }

  condition:
    any of them
}