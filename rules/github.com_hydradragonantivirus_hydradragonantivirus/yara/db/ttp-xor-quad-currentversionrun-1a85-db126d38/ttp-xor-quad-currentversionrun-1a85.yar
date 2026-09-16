rule TTP_XOR_QUAD_CurrentVersionRun_1a85 {
  strings:
    $key_1a85 = { 49 ea [2] 6d e4 [2] 46 c8 [2] 68 ea [2] 7c f1 [2] 73 eb [2] 6d f6 [2] 6f f7 [2] 74 f1 [2] 68 f6 [2] 74 d9 }

  condition:
    any of them
}