rule TTP_XOR_QUAD_CurrentVersionRun_0384 {
  strings:
    $key_0384 = { 50 eb [2] 74 e5 [2] 5f c9 [2] 71 eb [2] 65 f0 [2] 6a ea [2] 74 f7 [2] 76 f6 [2] 6d f0 [2] 71 f7 [2] 6d d8 }

  condition:
    any of them
}