rule TTP_XOR_QUAD_CurrentVersionRun_3384 {
  strings:
    $key_3384 = { 60 eb [2] 44 e5 [2] 6f c9 [2] 41 eb [2] 55 f0 [2] 5a ea [2] 44 f7 [2] 46 f6 [2] 5d f0 [2] 41 f7 [2] 5d d8 }

  condition:
    any of them
}