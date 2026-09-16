rule TTP_XOR_QUAD_CurrentVersionRun_069e {
  strings:
    $key_069e = { 55 f1 [2] 71 ff [2] 5a d3 [2] 74 f1 [2] 60 ea [2] 6f f0 [2] 71 ed [2] 73 ec [2] 68 ea [2] 74 ed [2] 68 c2 }

  condition:
    any of them
}