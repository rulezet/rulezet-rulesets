rule TTP_XOR_QUAD_CurrentVersionRun_1c9e {
  strings:
    $key_1c9e = { 4f f1 [2] 6b ff [2] 40 d3 [2] 6e f1 [2] 7a ea [2] 75 f0 [2] 6b ed [2] 69 ec [2] 72 ea [2] 6e ed [2] 72 c2 }

  condition:
    any of them
}