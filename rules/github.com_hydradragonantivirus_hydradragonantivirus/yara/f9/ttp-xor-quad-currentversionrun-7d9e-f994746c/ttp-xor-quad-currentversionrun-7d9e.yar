rule TTP_XOR_QUAD_CurrentVersionRun_7d9e {
  strings:
    $key_7d9e = { 2e f1 [2] 0a ff [2] 21 d3 [2] 0f f1 [2] 1b ea [2] 14 f0 [2] 0a ed [2] 08 ec [2] 13 ea [2] 0f ed [2] 13 c2 }

  condition:
    any of them
}