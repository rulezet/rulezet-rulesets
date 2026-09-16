rule TTP_XOR_QUAD_CurrentVersionRun_2d9e {
  strings:
    $key_2d9e = { 7e f1 [2] 5a ff [2] 71 d3 [2] 5f f1 [2] 4b ea [2] 44 f0 [2] 5a ed [2] 58 ec [2] 43 ea [2] 5f ed [2] 43 c2 }

  condition:
    any of them
}