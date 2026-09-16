rule TTP_XOR_QUAD_CurrentVersionRun_f59e {
  strings:
    $key_f59e = { a6 f1 [2] 82 ff [2] a9 d3 [2] 87 f1 [2] 93 ea [2] 9c f0 [2] 82 ed [2] 80 ec [2] 9b ea [2] 87 ed [2] 9b c2 }

  condition:
    any of them
}