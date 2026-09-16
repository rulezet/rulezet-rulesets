rule TTP_XOR_QUAD_CurrentVersionRun_6c9e {
  strings:
    $key_6c9e = { 3f f1 [2] 1b ff [2] 30 d3 [2] 1e f1 [2] 0a ea [2] 05 f0 [2] 1b ed [2] 19 ec [2] 02 ea [2] 1e ed [2] 02 c2 }

  condition:
    any of them
}