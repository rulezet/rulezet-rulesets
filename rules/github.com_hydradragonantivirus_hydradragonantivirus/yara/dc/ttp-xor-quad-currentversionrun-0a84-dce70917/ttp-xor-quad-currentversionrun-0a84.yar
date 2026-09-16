rule TTP_XOR_QUAD_CurrentVersionRun_0a84 {
  strings:
    $key_0a84 = { 59 eb [2] 7d e5 [2] 56 c9 [2] 78 eb [2] 6c f0 [2] 63 ea [2] 7d f7 [2] 7f f6 [2] 64 f0 [2] 78 f7 [2] 64 d8 }

  condition:
    any of them
}