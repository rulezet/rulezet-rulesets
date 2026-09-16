rule TTP_XOR_QUAD_CurrentVersionRun_779e {
  strings:
    $key_779e = { 24 f1 [2] 00 ff [2] 2b d3 [2] 05 f1 [2] 11 ea [2] 1e f0 [2] 00 ed [2] 02 ec [2] 19 ea [2] 05 ed [2] 19 c2 }

  condition:
    any of them
}