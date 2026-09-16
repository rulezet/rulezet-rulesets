rule TTP_XOR_QUAD_CurrentVersionRun_7684 {
  strings:
    $key_7684 = { 25 eb [2] 01 e5 [2] 2a c9 [2] 04 eb [2] 10 f0 [2] 1f ea [2] 01 f7 [2] 03 f6 [2] 18 f0 [2] 04 f7 [2] 18 d8 }

  condition:
    any of them
}