rule TTP_XOR_QUAD_CurrentVersionRun_2384 {
  strings:
    $key_2384 = { 70 eb [2] 54 e5 [2] 7f c9 [2] 51 eb [2] 45 f0 [2] 4a ea [2] 54 f7 [2] 56 f6 [2] 4d f0 [2] 51 f7 [2] 4d d8 }

  condition:
    any of them
}