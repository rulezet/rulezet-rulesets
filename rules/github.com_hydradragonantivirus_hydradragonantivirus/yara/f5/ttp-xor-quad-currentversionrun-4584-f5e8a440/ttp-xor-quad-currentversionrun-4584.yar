rule TTP_XOR_QUAD_CurrentVersionRun_4584 {
  strings:
    $key_4584 = { 16 eb [2] 32 e5 [2] 19 c9 [2] 37 eb [2] 23 f0 [2] 2c ea [2] 32 f7 [2] 30 f6 [2] 2b f0 [2] 37 f7 [2] 2b d8 }

  condition:
    any of them
}