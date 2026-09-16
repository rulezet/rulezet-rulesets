rule TTP_XOR_QUAD_CurrentVersionRun_0c9e {
  strings:
    $key_0c9e = { 5f f1 [2] 7b ff [2] 50 d3 [2] 7e f1 [2] 6a ea [2] 65 f0 [2] 7b ed [2] 79 ec [2] 62 ea [2] 7e ed [2] 62 c2 }

  condition:
    any of them
}