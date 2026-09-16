rule TTP_XOR_QUAD_CurrentVersionRun_ff8b {
  strings:
    $key_ff8b = { ac e4 [2] 88 ea [2] a3 c6 [2] 8d e4 [2] 99 ff [2] 96 e5 [2] 88 f8 [2] 8a f9 [2] 91 ff [2] 8d f8 [2] 91 d7 }

  condition:
    any of them
}