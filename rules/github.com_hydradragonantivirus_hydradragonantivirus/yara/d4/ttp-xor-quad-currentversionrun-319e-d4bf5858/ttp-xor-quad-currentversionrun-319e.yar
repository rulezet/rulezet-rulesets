rule TTP_XOR_QUAD_CurrentVersionRun_319e {
  strings:
    $key_319e = { 62 f1 [2] 46 ff [2] 6d d3 [2] 43 f1 [2] 57 ea [2] 58 f0 [2] 46 ed [2] 44 ec [2] 5f ea [2] 43 ed [2] 5f c2 }

  condition:
    any of them
}