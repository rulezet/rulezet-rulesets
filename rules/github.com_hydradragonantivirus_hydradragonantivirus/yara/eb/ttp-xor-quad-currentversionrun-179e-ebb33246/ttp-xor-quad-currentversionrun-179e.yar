rule TTP_XOR_QUAD_CurrentVersionRun_179e {
  strings:
    $key_179e = { 44 f1 [2] 60 ff [2] 4b d3 [2] 65 f1 [2] 71 ea [2] 7e f0 [2] 60 ed [2] 62 ec [2] 79 ea [2] 65 ed [2] 79 c2 }

  condition:
    any of them
}