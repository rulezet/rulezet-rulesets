rule TTP_XOR_QUAD_CurrentVersionRun_6a85 {
  strings:
    $key_6a85 = { 39 ea [2] 1d e4 [2] 36 c8 [2] 18 ea [2] 0c f1 [2] 03 eb [2] 1d f6 [2] 1f f7 [2] 04 f1 [2] 18 f6 [2] 04 d9 }

  condition:
    any of them
}